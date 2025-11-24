# Runtime Debug Flag Updates

This document describes how to update debug flags at runtime without restarting services, enabling dynamic debugging of production systems.

## Problem Statement

When debugging production issues, you need to enable debug logging without:
- Restarting the service (causes downtime)
- Redeploying (slow, risky)
- Changing code (not possible in production)

## Solution: Runtime Flag Updates

The debug library supports updating flags at runtime through multiple mechanisms:

1. **HTTP Admin Endpoint** (Recommended)
2. **gRPC Admin Service**
3. **Signal Handler** (SIGHUP to reload from file)
4. **File Watcher** (watch config file for changes)
5. **Configuration Service** (poll/watch external config)

## Implementation

**Note**: The debug library's `SetFlags()` method is already thread-safe and can be called at runtime. However, we need to add helper methods to:
- Get current enabled flags as a list
- Get current flags string
- Get all available flags

These methods would need to be added to the debug library, or implemented as wrappers.

### 1. HTTP Admin Endpoint

```go
// admin/debug_handler.go
package admin

import (
	"encoding/json"
	"net/http"
	
	debug "github.com/SCKelemen/debug"
)

// DebugAdminHandler provides HTTP endpoints for runtime debug flag management
type DebugAdminHandler struct {
	debugManager *debug.DebugManager
}

func NewDebugAdminHandler(dm *debug.DebugManager) *DebugAdminHandler {
	return &DebugAdminHandler{debugManager: dm}
}

// RegisterRoutes registers admin routes
func (h *DebugAdminHandler) RegisterRoutes(mux *http.ServeMux, basePath string) {
	path := basePath + "/debug"
	mux.HandleFunc(path+"/flags", h.HandleFlags)        // GET/PUT flags
	mux.HandleFunc(path+"/flags/enable", h.HandleEnable) // POST enable flags
	mux.HandleFunc(path+"/flags/disable", h.HandleDisable) // POST disable flags
	mux.HandleFunc(path+"/flags/list", h.HandleList)    // GET list all flags
}

// HandleFlags handles GET/PUT for debug flags
func (h *DebugAdminHandler) HandleFlags(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getFlags(w, r)
	case http.MethodPut:
		h.setFlags(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// getFlags returns current enabled flags
func (h *DebugAdminHandler) getFlags(w http.ResponseWriter, r *http.Request) {
	// Get enabled flags (would need to be implemented)
	enabled := getEnabledFlags(h.debugManager)
	
	resp := map[string]interface{}{
		"enabled_flags": enabled,
		"flags_string":  getFlagsString(h.debugManager), // Current flags string
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// setFlags updates debug flags from request body
func (h *DebugAdminHandler) setFlags(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Flags string `json:"flags"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request: %v", err), http.StatusBadRequest)
		return
	}
	
	// Update flags at runtime
	if err := h.debugManager.SetFlags(req.Flags); err != nil {
		http.Error(w, fmt.Sprintf("Failed to set flags: %v", err), http.StatusBadRequest)
		return
	}
	
	resp := map[string]interface{}{
		"status":        "success",
		"enabled_flags": getEnabledFlags(h.debugManager),
		"flags_string":  req.Flags,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

// Helper functions (would need to be implemented in debug library)
func getEnabledFlags(dm *debug.DebugManager) []string {
	// Would iterate through flagMap and check which flags are enabled
	// This is a placeholder - actual implementation would be in debug library
	return []string{} // Placeholder
}

func getAvailableFlags(dm *debug.DebugManager) []string {
	// Would return all registered flag names
	// This is a placeholder - actual implementation would be in debug library
	return []string{} // Placeholder
}

func getFlagsString(dm *debug.DebugManager) string {
	// Would return the current flags string that was last set
	// This requires storing the flags string in DebugManager
	// This is a placeholder - actual implementation would be in debug library
	return "" // Placeholder
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
	
	// Setup admin endpoints for runtime debug flag updates
	adminMux := http.NewServeMux()
	debugAdminHandler := admin.NewDebugAdminHandler(debugManager)
	debugAdminHandler.RegisterRoutes(adminMux, "/admin")
	
	// Secure admin endpoints with IAM
	adminHandler := interface.IAMMiddleware(iamEvaluator, map[string]iam.MethodAuthorizationOptions{
		"PUT:/admin/debug/flags": {
			Permission: "admin.debug.update",
			Strategy:   "before",
		},
		"POST:/admin/debug/flags/enable": {
			Permission: "admin.debug.update",
			Strategy:   "before",
		},
		"POST:/admin/debug/flags/disable": {
			Permission: "admin.debug.update",
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

1. **No Downtime**: Enable debugging without restarting
2. **Fast Response**: Enable flags in seconds, not minutes
3. **Selective Debugging**: Enable only what you need
4. **Production Safe**: Can disable flags immediately if needed
5. **Audit Trail**: All flag changes are logged

## Best Practices

1. **Default to Off**: Services start with minimal debug flags
2. **Time-Limited**: Consider auto-disabling flags after a timeout
3. **Resource Monitoring**: Monitor log volume when enabling flags
4. **Rollback Plan**: Always have a way to quickly disable flags
5. **Documentation**: Document which flags are safe for production

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Author**: Runtime Debug Flag Updates

