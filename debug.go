package debug

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DebugFlag represents a single debug flag
type DebugFlag uint64

// Context key for storing debug flags in context
type debugContextKey struct{}

// WithDebugFlags adds debug flags to the context
func WithDebugFlags(ctx context.Context, flags DebugFlag) context.Context {
	return context.WithValue(ctx, debugContextKey{}, flags)
}

// GetDebugFlagsFromContext retrieves debug flags from the context
func GetDebugFlagsFromContext(ctx context.Context) DebugFlag {
	if ctx == nil {
		return 0
	}
	if flags, ok := ctx.Value(debugContextKey{}).(DebugFlag); ok {
		return flags
	}
	return 0
}

// Severity represents the severity level of a debug message
type Severity int

const (
	SeverityTrace Severity = iota
	SeverityDebug
	SeverityInfo
	SeverityWarning
	SeverityError
	SeverityFatal
)

// String returns the string representation of the severity
func (s Severity) String() string {
	switch s {
	case SeverityTrace:
		return "TRACE"
	case SeverityDebug:
		return "DEBUG"
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARN"
	case SeverityError:
		return "ERROR"
	case SeverityFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// FlagDefinition represents a debug flag definition
type FlagDefinition struct {
	Flag DebugFlag
	Name string
	Path string
}

// PathSeverityFilter represents a severity filter for a specific path pattern
type PathSeverityFilter struct {
	Pattern string
	Filter  SeverityFilter
}

// SeverityFilter represents the type and configuration of a severity filter
type SeverityFilter struct {
	Type        SeverityFilterType
	Severities  map[Severity]bool // For specific severities
	MinSeverity Severity          // For minimum severity
}

// SeverityFilterType represents the type of severity filter
type SeverityFilterType int

const (
	SeverityFilterAll      SeverityFilterType = iota // Show all severities
	SeverityFilterMin                                // Show minimum severity and above
	SeverityFilterSpecific                           // Show only specific severities
)

// DebugManager manages debug flags and logging
type DebugManager struct {
	mu                   sync.RWMutex
	parser               FlagParser
	flagMap              map[string]DebugFlag
	pathMap              map[DebugFlag]string
	allFlags             []DebugFlag
	enabledFlags         DebugFlag
	pathSeverityFilters  []PathSeverityFilter
	globalSeverityFilter SeverityFilter
	logger               *slog.Logger
}

// NewDebugManager creates a new debug manager with the specified parser
func NewDebugManager(parser FlagParser) *DebugManager {
	return &DebugManager{
		parser:  parser,
		flagMap: make(map[string]DebugFlag),
		pathMap: make(map[DebugFlag]string),
	}
}

// NewDebugManagerWithSlog creates a new debug manager with slog integration
func NewDebugManagerWithSlog(parser FlagParser) *DebugManager {
	return &DebugManager{
		parser:  parser,
		flagMap: make(map[string]DebugFlag),
		pathMap: make(map[DebugFlag]string),
		logger:  slog.Default(),
	}
}

// NewDebugManagerWithSlogHandler creates a new debug manager with a custom slog handler
func NewDebugManagerWithSlogHandler(parser FlagParser, handler slog.Handler) *DebugManager {
	return &DebugManager{
		parser:  parser,
		flagMap: make(map[string]DebugFlag),
		pathMap: make(map[DebugFlag]string),
		logger:  slog.New(handler),
	}
}

// RegisterFlags registers debug flags with the manager
func (dm *DebugManager) RegisterFlags(definitions []FlagDefinition) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	for _, def := range definitions {
		dm.flagMap[def.Name] = def.Flag
		dm.pathMap[def.Flag] = def.Path
		dm.allFlags = append(dm.allFlags, def.Flag)
	}
}

// SetFlags sets the debug flags from a string using the configured parser
func (dm *DebugManager) SetFlags(flags string) error {
	if flags == "" {
		return nil
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Clear existing path severity filters
	dm.pathSeverityFilters = []PathSeverityFilter{}

	// Use the configured parser to parse flags
	enabledFlags, pathFilters, err := dm.parser.ParseFlags(flags, dm.flagMap, dm.pathMap)
	if err != nil {
		return err
	}

	dm.enabledFlags = enabledFlags
	dm.pathSeverityFilters = pathFilters
	return nil
}

// IsEnabled checks if a debug flag is enabled
func (dm *DebugManager) IsEnabled(flag DebugFlag) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.enabledFlags&flag != 0
}

// IsEnabledByName checks if a flag is enabled by name
func (dm *DebugManager) IsEnabledByName(name string) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if flag, exists := dm.flagMap[name]; exists {
		return dm.enabledFlags&flag != 0
	}
	return false
}

// Log writes a debug message if the flag is enabled
func (dm *DebugManager) Log(ctx context.Context, flag DebugFlag, format string, args ...interface{}) {
	dm.LogWithSeverity(ctx, flag, SeverityDebug, "", format, args...)
}

// LogWithContext writes a debug message with additional context
func (dm *DebugManager) LogWithContext(ctx context.Context, flag DebugFlag, contextStr string, format string, args ...interface{}) {
	dm.LogWithSeverity(ctx, flag, SeverityDebug, contextStr, format, args...)
}

// LogWithSeverity writes a debug message with severity level
func (dm *DebugManager) LogWithSeverity(ctx context.Context, flag DebugFlag, severity Severity, contextStr string, format string, args ...interface{}) {
	if dm.shouldLog(ctx, flag, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getPathWithContext(ctx, flag)

		if dm.logger != nil {
			// Use structured logging with slog
			attrs := []slog.Attr{
				slog.String("flag", path),
				slog.String("severity", severity.String()),
			}
			if contextStr != "" {
				attrs = append(attrs, slog.String("context", contextStr))
			}

			dm.logger.LogAttrs(ctx, dm.severityToSlogLevel(severity), message, attrs...)
		} else {
			// Use traditional logging
			if contextStr != "" {
				fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, contextStr, message)
			} else {
				fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
			}
		}
	}
}

// shouldLog determines if a message should be logged based on flag and severity
func (dm *DebugManager) shouldLog(ctx context.Context, flag DebugFlag, severity Severity) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Get context flags from the context parameter
	contextFlags := GetDebugFlagsFromContext(ctx)

	// Check if the current flag is enabled
	if dm.enabledFlags&flag != 0 {
		// Check severity filters
		path := dm.pathMap[flag]
		if dm.shouldLogWithPathSeverity(path, severity) {
			return true
		}
		if len(dm.pathSeverityFilters) > 0 {
			return false
		}
		return severity >= dm.globalSeverityFilter.MinSeverity
	}

	// Check if any context flags are enabled (inheritance)
	if contextFlags != 0 && dm.enabledFlags&contextFlags != 0 {
		// Check severity filters
		path := dm.pathMap[flag]
		if dm.shouldLogWithPathSeverity(path, severity) {
			return true
		}
		if len(dm.pathSeverityFilters) > 0 {
			return false
		}
		return severity >= dm.globalSeverityFilter.MinSeverity
	}

	return false
}

// shouldLogWithPathSeverity checks if a message should be logged based on path-specific severity filters
func (dm *DebugManager) shouldLogWithPathSeverity(path string, severity Severity) bool {
	for _, filter := range dm.pathSeverityFilters {
		if dm.matchesGlob(path, filter.Pattern) {
			return dm.checkSeverityFilter(severity, filter.Filter)
		}
	}
	return false
}

// checkSeverityFilter checks if a severity matches the given filter
func (dm *DebugManager) checkSeverityFilter(severity Severity, filter SeverityFilter) bool {
	switch filter.Type {
	case SeverityFilterAll:
		return true
	case SeverityFilterMin:
		return severity >= filter.MinSeverity
	case SeverityFilterSpecific:
		return filter.Severities[severity]
	default:
		return false
	}
}

// matchesGlob checks if a path matches a glob pattern
func (dm *DebugManager) matchesGlob(path, pattern string) bool {
	// Handle ** pattern (recursive match)
	if strings.Contains(pattern, "**") {
		// Convert ** pattern to a more flexible matching
		parts := strings.Split(pattern, "**")
		if len(parts) == 2 {
			prefix := strings.TrimSuffix(parts[0], ".")
			suffix := strings.TrimPrefix(parts[1], ".")

			if prefix != "" && !strings.HasPrefix(path, prefix) {
				return false
			}
			if suffix != "" && !strings.HasSuffix(path, suffix) {
				return false
			}
			return true
		}
	}

	// Use standard filepath.Match for other patterns
	matched, _ := filepath.Match(pattern, path)
	return matched
}

// getPathWithContext returns the path string for the given flag
func (dm *DebugManager) getPathWithContext(ctx context.Context, flag DebugFlag) string {
	path := dm.pathMap[flag]
	if path == "" {
		path = "unknown"
	}
	return path
}

// IsSlogEnabled returns whether slog integration is enabled
func (dm *DebugManager) IsSlogEnabled() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.logger != nil
}

// severityToSlogLevel converts our Severity to slog.Level
func (dm *DebugManager) severityToSlogLevel(severity Severity) slog.Level {
	switch severity {
	case SeverityTrace:
		return slog.LevelDebug - 1 // Trace is below Debug
	case SeverityDebug:
		return slog.LevelDebug
	case SeverityInfo:
		return slog.LevelInfo
	case SeverityWarning:
		return slog.LevelWarn
	case SeverityError:
		return slog.LevelError
	case SeverityFatal:
		return slog.LevelError + 1 // Fatal is above Error
	default:
		return slog.LevelInfo
	}
}
