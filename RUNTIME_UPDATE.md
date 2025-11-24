# Runtime Configuration Management

This document describes how to update runtime configuration at runtime without restarting services, enabling dynamic control of:
- **Debug Flags**: Enable/disable debug logging for specific paths
- **Lifecycle Logging**: Control lifecycle event emission levels
- **Feature Flags**: Enable/disable features dynamically
- **Tracing**: Control OpenTelemetry tracing sampling rates
- **Metrics**: Enable/disable specific metrics collection
- **Other Observability**: Log levels, sampling rates, etc.

## Problem Statement

When debugging production issues or managing runtime behavior, you need to update configuration without:
- Restarting the service (causes downtime)
- Redeploying (slow, risky)
- Changing code (not possible in production)

## Unified Runtime Configuration

All runtime configuration should be managed through a unified interface that supports:
1. **HTTP Admin Endpoint** (Recommended)
2. **gRPC Admin Service**
3. **Signal Handler** (SIGHUP to reload from file)
4. **File Watcher** (watch config file for changes)
5. **Configuration Service** (poll/watch external config)

## Solution: Unified Runtime Configuration

Runtime configuration is managed through a unified admin interface supporting multiple mechanisms:

1. **HTTP Admin Endpoint** (Recommended)
2. **gRPC Admin Service**
3. **Signal Handler** (SIGHUP to reload from file)
4. **File Watcher** (watch config file for changes)
5. **Configuration Service** (poll/watch external config)

## Implementation

**Note**: The debug library's `SetFlags()` method is already thread-safe and can be called at runtime. The library includes helper methods:
- `GetEnabledFlags()` - Returns list of currently enabled flag names
- `GetAvailableFlags()` - Returns list of all registered flag names
- `GetFlagsString()` - Returns the current flags string that was last set

These methods are thread-safe and can be used for runtime flag management.

### 1. HTTP Admin Endpoint

```go
// admin/runtime_config_handler.go
package admin

import (
	"encoding/json"
	"net/http"
	
	debug "github.com/SCKelemen/debug"
	"github.com/SCKelemen/lifecycle"
)

// RuntimeConfig represents all runtime configuration
type RuntimeConfig struct {
	DebugFlags      *DebugFlagsConfig      `json:"debug_flags,omitempty"`
	LifecycleLogging *LifecycleLoggingConfig `json:"lifecycle_logging,omitempty"`
	FeatureFlags    *FeatureFlagsConfig    `json:"feature_flags,omitempty"`
	Tracing         *TracingConfig         `json:"tracing,omitempty"`
	Metrics         *MetricsConfig         `json:"metrics,omitempty"`
}

// DebugFlagsConfig represents debug flag configuration
type DebugFlagsConfig struct {
	Enabled string `json:"enabled"` // Flags string (e.g., "http.request|db.query")
}

// LifecycleLoggingConfig represents lifecycle event logging configuration
type LifecycleLoggingConfig struct {
	Level              string            `json:"level"`                // "all", "errors", "none"
	EventTypes         []string          `json:"event_types,omitempty"` // Specific event types to log
	SamplingRate       float64           `json:"sampling_rate,omitempty"` // 0.0 to 1.0
	DisablePIIRedaction bool             `json:"disable_pii_redaction,omitempty"` // Dangerous!
}

// FeatureFlagsConfig represents feature flag configuration
type FeatureFlagsConfig struct {
	Flags map[string]bool `json:"flags"` // feature_name -> enabled
}

// TracingConfig represents OpenTelemetry tracing configuration
type TracingConfig struct {
	Enabled      bool    `json:"enabled"`
	SamplingRate float64 `json:"sampling_rate"` // 0.0 to 1.0
	MaxSpans     int     `json:"max_spans,omitempty"`
}

// MetricsConfig represents metrics collection configuration
type MetricsConfig struct {
	Enabled      bool     `json:"enabled"`
	DisableTypes []string `json:"disable_types,omitempty"` // ["counter", "gauge", "histogram"]
}

// RuntimeConfigHandler provides HTTP endpoints for runtime configuration management
type RuntimeConfigHandler struct {
	debugManager    *debug.DebugManager
	lifecycleProducer *lifecycle.Producer
	featureFlags    *FeatureFlagManager
	tracingConfig   *TracingConfigManager
	metricsConfig   *MetricsConfigManager
}

func NewRuntimeConfigHandler(
	dm *debug.DebugManager,
	producer *lifecycle.Producer,
	featureFlags *FeatureFlagManager,
	tracing *TracingConfigManager,
	metrics *MetricsConfigManager,
) *RuntimeConfigHandler {
	return &RuntimeConfigHandler{
		debugManager:      dm,
		lifecycleProducer: producer,
		featureFlags:      featureFlags,
		tracingConfig:     tracing,
		metricsConfig:     metrics,
	}
}

// RegisterRoutes registers admin routes
func (h *RuntimeConfigHandler) RegisterRoutes(mux *http.ServeMux, basePath string) {
	path := basePath + "/runtime"
	
	// Unified configuration endpoint
	mux.HandleFunc(path+"/config", h.HandleConfig)        // GET/PUT all config
	mux.HandleFunc(path+"/config/debug", h.HandleDebugFlags) // GET/PUT debug flags
	mux.HandleFunc(path+"/config/lifecycle", h.HandleLifecycle) // GET/PUT lifecycle logging
	mux.HandleFunc(path+"/config/features", h.HandleFeatureFlags) // GET/PUT feature flags
	mux.HandleFunc(path+"/config/tracing", h.HandleTracing) // GET/PUT tracing config
	mux.HandleFunc(path+"/config/metrics", h.HandleMetrics) // GET/PUT metrics config
}

// HandleConfig handles GET/PUT for all runtime configuration
func (h *RuntimeConfigHandler) HandleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getConfig(w, r)
	case http.MethodPut:
		h.setConfig(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getConfig returns current runtime configuration
func (h *RuntimeConfigHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	config := RuntimeConfig{
		DebugFlags: &DebugFlagsConfig{
			Enabled: h.debugManager.GetFlagsString(),
		},
		LifecycleLogging: h.getLifecycleConfig(),
		FeatureFlags:    h.featureFlags.GetConfig(),
		Tracing:         h.tracingConfig.GetConfig(),
		Metrics:         h.metricsConfig.GetConfig(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// setConfig updates runtime configuration
func (h *RuntimeConfigHandler) setConfig(w http.ResponseWriter, r *http.Request) {
	var config RuntimeConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	// Update each component
	if config.DebugFlags != nil {
		if err := h.debugManager.SetFlags(config.DebugFlags.Enabled); err != nil {
			http.Error(w, fmt.Sprintf("Failed to set debug flags: %v", err), http.StatusBadRequest)
			return
		}
	}
	
	if config.LifecycleLogging != nil {
		if err := h.setLifecycleConfig(config.LifecycleLogging); err != nil {
			http.Error(w, fmt.Sprintf("Failed to set lifecycle config: %v", err), http.StatusBadRequest)
			return
		}
	}
	
	if config.FeatureFlags != nil {
		h.featureFlags.SetConfig(config.FeatureFlags)
	}
	
	if config.Tracing != nil {
		h.tracingConfig.SetConfig(config.Tracing)
	}
	
	if config.Metrics != nil {
		h.metricsConfig.SetConfig(config.Metrics)
	}
	
	// Return updated config
	h.getConfig(w, r)
}

// HandleDebugFlags handles GET/PUT for debug flags only
func (h *RuntimeConfigHandler) HandleDebugFlags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getDebugFlags(w, r)
	case http.MethodPut:
		h.setDebugFlags(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getDebugFlags returns current debug flags
func (h *RuntimeConfigHandler) getDebugFlags(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"enabled_flags": h.debugManager.GetEnabledFlags(),
		"available_flags": h.debugManager.GetAvailableFlags(),
		"flags_string":  h.debugManager.GetFlagsString(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// setDebugFlags updates debug flags from request body
func (h *RuntimeConfigHandler) setDebugFlags(w http.ResponseWriter, r *http.Request) {
	var req DebugFlagsConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	// Update flags at runtime
	if err := h.debugManager.SetFlags(req.Enabled); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set flags: %v", err), http.StatusBadRequest)
		return
	}
	
	resp := map[string]interface{}{
		"status":        "success",
		"enabled_flags": h.debugManager.GetEnabledFlags(),
		"flags_string":  req.Enabled,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleLifecycle handles GET/PUT for lifecycle logging configuration
func (h *RuntimeConfigHandler) HandleLifecycle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getLifecycleConfigHandler(w, r)
	case http.MethodPut:
		h.setLifecycleConfigHandler(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *RuntimeConfigHandler) getLifecycleConfigHandler(w http.ResponseWriter, r *http.Request) {
	config := h.getLifecycleConfig()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (h *RuntimeConfigHandler) setLifecycleConfigHandler(w http.ResponseWriter, r *http.Request) {
	var config LifecycleLoggingConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	if err := h.setLifecycleConfig(&config); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set lifecycle config: %v", err), http.StatusBadRequest)
		return
	}
	
	h.getLifecycleConfigHandler(w, r)
}

func (h *RuntimeConfigHandler) getLifecycleConfig() *LifecycleLoggingConfig {
	// Get current lifecycle producer configuration
	// This would need to be implemented in lifecycle library
	return &LifecycleLoggingConfig{
		Level:        "all",
		SamplingRate: 1.0,
	}
}

func (h *RuntimeConfigHandler) setLifecycleConfig(config *LifecycleLoggingConfig) error {
	// Update lifecycle producer configuration
	// This would need to be implemented in lifecycle library
	return nil
}

// HandleFeatureFlags handles GET/PUT for feature flags
func (h *RuntimeConfigHandler) HandleFeatureFlags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.featureFlags.GetConfig())
	case http.MethodPut:
		var config FeatureFlagsConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}
		h.featureFlags.SetConfig(&config)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.featureFlags.GetConfig())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleTracing handles GET/PUT for tracing configuration
func (h *RuntimeConfigHandler) HandleTracing(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.tracingConfig.GetConfig())
	case http.MethodPut:
		var config TracingConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}
		h.tracingConfig.SetConfig(&config)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.tracingConfig.GetConfig())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleMetrics handles GET/PUT for metrics configuration
func (h *RuntimeConfigHandler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.metricsConfig.GetConfig())
	case http.MethodPut:
		var config MetricsConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
			return
		}
		h.metricsConfig.SetConfig(&config)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(h.metricsConfig.GetConfig())
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleEnable enables specific flags (additive)
func (h *DebugAdminHandler) HandleEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Flags string `json:"flags"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	// Get current flags (would need to store current flags string)
	current := getFlagsString(h.debugManager)
	
	// Merge with new flags
	var newFlags string
	if current == "" {
		newFlags = req.Flags
	} else {
		newFlags = current + "," + req.Flags
	}
	
	if err := h.debugManager.SetFlags(newFlags); err != nil {
		http.Error(w, fmt.Sprintf("Failed to enable flags: %v", err), http.StatusBadRequest)
		return
	}
	
	resp := map[string]interface{}{
		"status":        "success",
		"enabled_flags": getEnabledFlags(h.debugManager),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleDisable disables specific flags
func (h *DebugAdminHandler) HandleDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Flags string `json:"flags"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	// Get current flags and remove specified ones
	current := getFlagsString(h.debugManager)
	newFlags := removeFlags(current, req.Flags)
	
	if err := h.debugManager.SetFlags(newFlags); err != nil {
		http.Error(w, fmt.Sprintf("Failed to disable flags: %v", err), http.StatusBadRequest)
		return
	}
	
	resp := map[string]interface{}{
		"status":        "success",
		"enabled_flags": getEnabledFlags(h.debugManager),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// HandleList returns all available flags
func (h *DebugAdminHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	available := getAvailableFlags(h.debugManager)
	enabled := getEnabledFlags(h.debugManager)
	
	resp := map[string]interface{}{
		"available_flags": available,
		"enabled_flags":   enabled,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func removeFlags(current, toRemove string) string {
	// Simple implementation - in practice would parse and remove flags
	// This is a placeholder
	return current // Would actually remove flags
}
```

### 2. gRPC Admin Service

```go
// admin/debug_service.go
package admin

import (
	"context"
	
	debug "github.com/SCKelemen/debug"
	adminv1 "github.com/SCKelemen/api/generated/admin/proto/adminv1"
)

// DebugAdminService provides gRPC endpoints for runtime debug flag management
type DebugAdminService struct {
	adminv1.UnimplementedDebugAdminServiceServer
	debugManager *debug.DebugManager
}

func NewDebugAdminService(dm *debug.DebugManager) *DebugAdminService {
	return &DebugAdminService{debugManager: dm}
}

// SetFlags updates debug flags
func (s *DebugAdminService) SetFlags(ctx context.Context, req *adminv1.SetDebugFlagsRequest) (*adminv1.SetDebugFlagsResponse, error) {
	if err := s.debugManager.SetFlags(req.Flags); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	
	return &adminv1.SetDebugFlagsResponse{
		EnabledFlags: getEnabledFlags(s.debugManager),
		FlagsString:  req.Flags,
	}, nil
}

// GetFlags returns current enabled flags
func (s *DebugAdminService) GetFlags(ctx context.Context, req *adminv1.GetDebugFlagsRequest) (*adminv1.GetDebugFlagsResponse, error) {
	return &adminv1.GetDebugFlagsResponse{
		EnabledFlags: getEnabledFlags(s.debugManager),
		FlagsString:  getFlagsString(s.debugManager),
	}, nil
}

// EnableFlags enables specific flags (additive)
func (s *DebugAdminService) EnableFlags(ctx context.Context, req *adminv1.EnableDebugFlagsRequest) (*adminv1.EnableDebugFlagsResponse, error) {
	current := getFlagsString(s.debugManager)
	var newFlags string
	if current == "" {
		newFlags = req.Flags
	} else {
		newFlags = current + "," + req.Flags
	}
	
	if err := s.debugManager.SetFlags(newFlags); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	
	return &adminv1.EnableDebugFlagsResponse{
		EnabledFlags: getEnabledFlags(s.debugManager),
	}, nil
}

// DisableFlags disables specific flags
func (s *DebugAdminService) DisableFlags(ctx context.Context, req *adminv1.DisableDebugFlagsRequest) (*adminv1.DisableDebugFlagsResponse, error) {
	// Remove flags from current set
	current := getFlagsString(s.debugManager)
	newFlags := removeFlags(current, req.Flags)
	
	if err := s.debugManager.SetFlags(newFlags); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	
	return &adminv1.DisableDebugFlagsResponse{
		EnabledFlags: getEnabledFlags(s.debugManager),
	}, nil
}

// Helper functions (use methods from debug library)
func getEnabledFlags(dm *debug.DebugManager) []string {
	return dm.GetEnabledFlags()
}

func getAvailableFlags(dm *debug.DebugManager) []string {
	return dm.GetAvailableFlags()
}

func getFlagsString(dm *debug.DebugManager) string {
	return dm.GetFlagsString()
}
```

### 3. Signal Handler (SIGHUP Reload)

```go
// admin/signal_handler.go
package admin

import (
	"os"
	"os/signal"
	"syscall"
	
	debug "github.com/SCKelemen/debug"
)

// SetupSignalHandler sets up SIGHUP handler to reload debug flags from file
func SetupSignalHandler(dm *debug.DebugManager, configFile string) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	
	go func() {
		for {
			<-sigChan
			// Reload flags from file
			if flags, err := os.ReadFile(configFile); err == nil {
				if err := dm.SetFlags(string(flags)); err == nil {
					log.Printf("Debug flags reloaded from %s: %s", configFile, string(flags))
				} else {
					log.Printf("Failed to reload debug flags: %v", err)
				}
			} else {
				log.Printf("Failed to read debug flags file: %v", err)
			}
		}
	}()
}
```

### 4. File Watcher

```go
// admin/file_watcher.go
package admin

import (
	"os"
	"time"
	
	debug "github.com/SCKelemen/debug"
	"github.com/fsnotify/fsnotify"
)

// WatchDebugFlagsFile watches a file for changes and updates debug flags
func WatchDebugFlagsFile(dm *debug.DebugManager, configFile string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	
	if err := watcher.Add(configFile); err != nil {
		return err
	}
	
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					// File was modified, reload flags
					time.Sleep(100 * time.Millisecond) // Debounce
					if flags, err := os.ReadFile(configFile); err == nil {
						if err := dm.SetFlags(string(flags)); err == nil {
							log.Printf("Debug flags updated from file: %s", string(flags))
						}
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("File watcher error: %v", err)
			}
		}
	}()
	
	return nil
}
```

### 5. Configuration Service Integration

```go
// admin/config_service.go
package admin

import (
	"context"
	"time"
	
	debug "github.com/SCKelemen/debug"
)

// PollConfigService polls a configuration service for debug flag updates
func PollConfigService(dm *debug.DebugManager, configService ConfigServiceClient, serviceID string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			flags, err := configService.GetDebugFlags(context.Background(), serviceID)
			if err != nil {
				log.Printf("Failed to get debug flags from config service: %v", err)
				continue
			}
			
			if err := dm.SetFlags(flags); err != nil {
				log.Printf("Failed to update debug flags: %v", err)
				continue
			}
			
			log.Printf("Debug flags updated from config service: %s", flags)
		}
	}
}
```

## Security Considerations

### Authorization

Runtime debug flag updates should be **heavily restricted**:

1. **Admin-only endpoints**: Require admin authentication
2. **IAM authorization**: Require `admin.debug.update` permission
3. **Network isolation**: Admin endpoints on separate port/network
4. **Audit logging**: Log all flag changes with actor information

```go
// Secure admin handler with IAM
func (h *DebugAdminHandler) setFlags(w http.ResponseWriter, r *http.Request) {
	// Extract caller from context (set by IAM middleware)
	c := caller.FromContext(r.Context())
	if c == nil {
		http.Error(w, "Unauthenticated", http.StatusUnauthorized)
		return
	}
	
	// Check admin permission
	allowed, err := h.iamEvaluator.Evaluate(r.Context(), c, "admin", "admin.debug.update")
	if err != nil || !allowed {
		http.Error(w, "Permission denied", http.StatusForbidden)
		return
	}
	
	// Audit log the change
	oldFlags := getFlagsString(h.debugManager)
	h.auditLogger.Log(r.Context(), "debug_flags_updated", map[string]interface{}{
		"actor": c.Principal(),
		"old_flags": oldFlags,
		"new_flags": req.Flags,
	})
	
	// Update flags
	// ...
}
```

### Rate Limiting

Prevent abuse with rate limiting:

```go
// Rate limit flag updates
var flagUpdateLimiter = rate.NewLimiter(rate.Every(1*time.Second), 5) // 5 per second

func (h *DebugAdminHandler) setFlags(w http.ResponseWriter, r *http.Request) {
	if !flagUpdateLimiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	// ...
}
```

## Usage Examples

### Enable Debug Flags via HTTP

```bash
# Enable all HTTP request debugging
curl -X PUT http://localhost:8080/admin/debug/flags \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"flags": "http.request"}'

# Enable multiple flags
curl -X PUT http://localhost:8080/admin/debug/flags \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"flags": "http.request|db.query|secretmanager.secretversion.access"}'

# Add flags (additive)
curl -X POST http://localhost:8080/admin/debug/flags/enable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"flags": "api.user.create"}'

# Remove flags
curl -X POST http://localhost:8080/admin/debug/flags/disable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"flags": "http.request"}'

# List current flags
curl http://localhost:8080/admin/debug/flags/list \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Enable via SIGHUP

```bash
# Write flags to file
echo "http.request|db.query" > /var/run/debug-flags.conf

# Send SIGHUP to reload
kill -HUP $(pgrep secret-manager-service)
```

### Enable via File Watcher

```bash
# File watcher automatically picks up changes
echo "http.request|db.query" > /var/run/debug-flags.conf
# Flags updated automatically within 100ms
```

## Integration in Generated Services

### Updated main.go

```go
func main() {
	// ... existing initialization ...
	
	// Initialize runtime configuration managers
	featureFlagManager := featureflags.NewManager()
	tracingConfigManager := tracing.NewConfigManager(otelTracerProvider)
	metricsConfigManager := metrics.NewConfigManager(otelMeterProvider)
	
	// Setup admin endpoints for runtime configuration updates
	adminMux := http.NewServeMux()
	runtimeConfigHandler := admin.NewRuntimeConfigHandler(
		debugManager,
		producer,
		featureFlagManager,
		tracingConfigManager,
		metricsConfigManager,
	)
	runtimeConfigHandler.RegisterRoutes(adminMux, "/admin")
	
	// Secure admin endpoints with IAM
	adminHandler := interface.IAMMiddleware(iamEvaluator, map[string]iam.MethodAuthorizationOptions{
		"PUT:/admin/runtime/config": {
			Permission: "admin.runtime.update",
			Strategy:   "before",
		},
		"PUT:/admin/runtime/config/debug": {
			Permission: "admin.debug.update",
			Strategy:   "before",
		},
		"PUT:/admin/runtime/config/lifecycle": {
			Permission: "admin.lifecycle.update",
			Strategy:   "before",
		},
		"PUT:/admin/runtime/config/features": {
			Permission: "admin.features.update",
			Strategy:   "before",
		},
		"PUT:/admin/runtime/config/tracing": {
			Permission: "admin.tracing.update",
			Strategy:   "before",
		},
		"PUT:/admin/runtime/config/metrics": {
			Permission: "admin.metrics.update",
			Strategy:   "before",
		},
	})(adminMux)
	
	// Start admin server on separate port
	adminServer := &http.Server{
		Addr:    ":8081", // Separate port for admin
		Handler: adminHandler,
	}
	
	go func() {
		log.Println("Starting admin server on :8081")
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Admin server failed: %v", err)
		}
	}()
	
	// Optionally: Setup file watcher
	if configFile := os.Getenv("DEBUG_FLAGS_FILE"); configFile != "" {
		if err := admin.WatchDebugFlagsFile(debugManager, configFile); err != nil {
			log.Printf("Failed to setup file watcher: %v", err)
		}
	}
	
	// Optionally: Setup SIGHUP handler
	admin.SetupSignalHandler(debugManager, os.Getenv("DEBUG_FLAGS_FILE"))
	
	// ... rest of service startup ...
}
```

## Benefits

1. **No Downtime**: Update configuration without restarting
2. **Fast Response**: Update config in seconds, not minutes
3. **Selective Control**: Enable/disable specific features independently
4. **Production Safe**: Can revert changes immediately if needed
5. **Unified Interface**: Single endpoint for all runtime configuration
6. **Audit Trail**: All configuration changes are logged
7. **Resource Management**: Control observability overhead (sampling rates, log levels)
8. **Feature Management**: Enable/disable features without code changes

## Best Practices

1. **Default to Safe**: Services start with conservative configuration
   - Minimal debug flags
   - Error-level lifecycle logging
   - Low tracing sampling rates
   - All features disabled by default
2. **Time-Limited**: Consider auto-reverting configuration after a timeout
3. **Resource Monitoring**: Monitor resource usage when enabling features
   - Log volume (lifecycle events)
   - Trace volume (tracing)
   - CPU/memory (metrics collection)
4. **Rollback Plan**: Always have a way to quickly revert changes
5. **Documentation**: Document which configurations are safe for production
6. **Gradual Rollout**: Enable features gradually (per service, per region)
7. **Feature Flags**: Use feature flags for new functionality, not just debugging

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Author**: Runtime Debug Flag Updates

