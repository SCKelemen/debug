package debug

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DebugFlag represents a debug flag (can be a single flag or multiple combined flags)
// It's implemented as a slice of uint64 to support more than 64 flags.
// Each uint64 holds 64 flags, so flag N is at bit (N % 64) in slice[N/64].
type DebugFlag []uint64

// NewDebugFlag creates a new DebugFlag with a single bit set at the given position
func NewDebugFlag(bitPosition int) DebugFlag {
	if bitPosition < 0 {
		return nil
	}
	sliceIndex := bitPosition / 64
	bitIndex := uint(bitPosition % 64)
	flags := make(DebugFlag, sliceIndex+1)
	flags[sliceIndex] = 1 << bitIndex
	return flags
}

// DebugFlagFromUint64 creates a DebugFlag from a uint64 value (for backward compatibility)
// This allows existing code like DebugFlag(1 << 0) to work by converting uint64 to []uint64
func DebugFlagFromUint64(val uint64) DebugFlag {
	if val == 0 {
		return nil
	}
	return DebugFlag{val}
}

// HasFlag checks if the given flag is set (fast path - only checks relevant slice element)
func (f DebugFlag) HasFlag(flag DebugFlag) bool {
	if len(flag) == 0 {
		return false
	}
	// Find the highest bit position in the flag to determine which slice elements to check
	for i := len(flag) - 1; i >= 0; i-- {
		if flag[i] != 0 {
			if i >= len(f) {
				return false
			}
			if f[i]&flag[i] != 0 {
				return true
			}
		}
	}
	return false
}

// Or combines two flags using OR operation
func (f DebugFlag) Or(other DebugFlag) DebugFlag {
	maxLen := len(f)
	if len(other) > maxLen {
		maxLen = len(other)
	}
	if maxLen == 0 {
		return nil
	}
	result := make(DebugFlag, maxLen)
	for i := 0; i < maxLen; i++ {
		var left, right uint64
		if i < len(f) {
			left = f[i]
		}
		if i < len(other) {
			right = other[i]
		}
		result[i] = left | right
	}
	return result
}

// And combines two flags using AND operation
func (f DebugFlag) And(other DebugFlag) DebugFlag {
	maxLen := len(f)
	if len(other) < maxLen {
		maxLen = len(other)
	}
	if maxLen == 0 {
		return nil
	}
	result := make(DebugFlag, maxLen)
	for i := 0; i < maxLen; i++ {
		result[i] = f[i] & other[i]
	}
	return result
}

// AndNot performs AND NOT operation (f &^ other)
func (f DebugFlag) AndNot(other DebugFlag) DebugFlag {
	if len(f) == 0 {
		return nil
	}
	result := make(DebugFlag, len(f))
	for i := 0; i < len(f); i++ {
		var otherVal uint64
		if i < len(other) {
			otherVal = other[i]
		}
		result[i] = f[i] &^ otherVal
	}
	return result
}

// IsZero checks if the flag has no bits set
func (f DebugFlag) IsZero() bool {
	for i := 0; i < len(f); i++ {
		if f[i] != 0 {
			return false
		}
	}
	return true
}

// MethodContext represents a method-scoped context for debug flags
type MethodContext struct {
	flags DebugFlag
	dm    *DebugManager
}

// LogOption represents an option for logging
type LogOption func(*logOptions)

// logOptions holds the options for a log call
type logOptions struct {
	additionalFlags DebugFlag
	severity        Severity
	attrs           []slog.Attr
}

// WithFlag adds a single additional flag to the log call
func WithFlag(flag DebugFlag) LogOption {
	return func(opts *logOptions) {
		if opts.additionalFlags == nil {
			opts.additionalFlags = flag
		} else {
			opts.additionalFlags = opts.additionalFlags.Or(flag)
		}
	}
}

// WithFlags adds multiple additional flags to the log call
func WithFlags(flags ...DebugFlag) LogOption {
	return func(opts *logOptions) {
		for _, flag := range flags {
			if opts.additionalFlags == nil {
				opts.additionalFlags = flag
			} else {
				opts.additionalFlags = opts.additionalFlags.Or(flag)
			}
		}
	}
}

// WithSeverity sets the severity for the log call
func WithSeverity(severity Severity) LogOption {
	return func(opts *logOptions) {
		opts.severity = severity
	}
}

// WithAttr adds a structured attribute to the log call
func WithAttr(attr slog.Attr) LogOption {
	return func(opts *logOptions) {
		opts.attrs = append(opts.attrs, attr)
	}
}

// WithAttrs adds multiple structured attributes to the log call
func WithAttrs(attrs []slog.Attr) LogOption {
	return func(opts *logOptions) {
		opts.attrs = append(opts.attrs, attrs...)
	}
}

// WithMethodContext creates a new method context with the given flags
func (dm *DebugManager) WithMethodContext(flags DebugFlag) *MethodContext {
	return &MethodContext{
		flags: flags,
		dm:    dm,
	}
}

// Log writes a debug message using the method context flags
func (mc *MethodContext) Log(format string, args ...interface{}) {
	mc.dm.LogWithMethodContext(mc.flags, mc.flags, format, args...)
}

// Debug writes a debug message using method context flags with optional options
func (mc *MethodContext) Debug(msg interface{}, opts ...LogOption) {
	mc.logWithOptions(SeverityDebug, msg, opts...)
}

// Info writes an info message using method context flags with optional options
func (mc *MethodContext) Info(msg interface{}, opts ...LogOption) {
	mc.logWithOptions(SeverityInfo, msg, opts...)
}

// Warn writes a warning message using method context flags with optional options
func (mc *MethodContext) Warn(msg interface{}, opts ...LogOption) {
	mc.logWithOptions(SeverityWarning, msg, opts...)
}

// Error writes an error message using method context flags with optional options
func (mc *MethodContext) Error(msg interface{}, opts ...LogOption) {
	mc.logWithOptions(SeverityError, msg, opts...)
}

// logWithOptions handles the common logic for option-based logging
func (mc *MethodContext) logWithOptions(defaultSeverity Severity, msg interface{}, opts ...LogOption) {
	// Parse options
	options := &logOptions{
		severity:        defaultSeverity,
		additionalFlags: nil, // Initialize as nil (empty slice)
	}
	for _, opt := range opts {
		opt(options)
	}

	// Combine method context flags with additional flags
	var combinedFlags DebugFlag
	if options.additionalFlags == nil || len(options.additionalFlags) == 0 {
		combinedFlags = mc.flags
	} else {
		combinedFlags = mc.flags.Or(options.additionalFlags)
	}

	// Format message
	var message string
	switch v := msg.(type) {
	case string:
		message = v
	case fmt.Stringer:
		message = v.String()
	default:
		message = fmt.Sprintf("%v", v)
	}

	mc.dm.LogWithMethodContextAndSeverityAndAttrs(mc.flags, combinedFlags, options.severity, "", message, options.attrs)
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
	flagDefinitions      []FlagDefinition // Store all flag definitions for path lookup
	allFlags             []DebugFlag
	enabledFlags         DebugFlag
	pathSeverityFilters  []PathSeverityFilter
	globalSeverityFilter SeverityFilter
	logger               *slog.Logger
}

// NewDebugManager creates a new debug manager with the specified parser
func NewDebugManager(parser FlagParser) *DebugManager {
	return &DebugManager{
		parser:          parser,
		flagMap:         make(map[string]DebugFlag),
		flagDefinitions: make([]FlagDefinition, 0),
	}
}

// NewDebugManagerWithSlog creates a new debug manager with slog integration
func NewDebugManagerWithSlog(parser FlagParser) *DebugManager {
	return &DebugManager{
		parser:          parser,
		flagMap:         make(map[string]DebugFlag),
		flagDefinitions: make([]FlagDefinition, 0),
		logger:          slog.Default(),
	}
}

// NewDebugManagerWithSlogHandler creates a new debug manager with a custom slog handler
func NewDebugManagerWithSlogHandler(parser FlagParser, handler slog.Handler) *DebugManager {
	return &DebugManager{
		parser:          parser,
		flagMap:         make(map[string]DebugFlag),
		flagDefinitions: make([]FlagDefinition, 0),
		logger:          slog.New(handler),
	}
}

// RegisterFlags registers debug flags with the manager
func (dm *DebugManager) RegisterFlags(definitions []FlagDefinition) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	for _, def := range definitions {
		dm.flagMap[def.Name] = def.Flag
		dm.flagDefinitions = append(dm.flagDefinitions, def)
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

	// Note: pathMap is no longer used since slices can't be map keys.
	// Parsers should use flagMap keys (which are paths) for glob pattern matching instead.
	// We pass nil for backward compatibility with the interface.

	// Use the configured parser to parse flags
	enabledFlags, pathFilters, err := dm.parser.ParseFlags(flags, dm.flagMap, nil)
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
	return dm.enabledFlags.HasFlag(flag)
}

// IsEnabledByName checks if a flag is enabled by name
func (dm *DebugManager) IsEnabledByName(name string) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if flag, exists := dm.flagMap[name]; exists {
		return dm.enabledFlags.HasFlag(flag)
	}
	return false
}

// Log writes a debug message if the flag is enabled
func (dm *DebugManager) Log(flag DebugFlag, format string, args ...interface{}) {
	dm.LogWithSeverity(flag, SeverityDebug, "", format, args...)
}

// LogWithMethodContext writes a debug message using method context flags
func (dm *DebugManager) LogWithMethodContext(methodFlags DebugFlag, flag DebugFlag, format string, args ...interface{}) {
	dm.LogWithMethodContextAndSeverity(methodFlags, flag, SeverityDebug, "", format, args...)
}

// LogWithSeverity writes a debug message with severity level
func (dm *DebugManager) LogWithSeverity(flag DebugFlag, severity Severity, contextStr string, format string, args ...interface{}) {
	if dm.shouldLog(nil, flag, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getPath(flag)

		if dm.logger != nil {
			// Use structured logging with slog
			attrs := []slog.Attr{
				slog.String("flag", path),
				slog.String("severity", severity.String()),
			}
			if contextStr != "" {
				attrs = append(attrs, slog.String("context", contextStr))
			}

			dm.logger.LogAttrs(nil, dm.severityToSlogLevel(severity), message, attrs...)
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

// LogWithMethodContextAndSeverity writes a debug message using method context flags with severity
func (dm *DebugManager) LogWithMethodContextAndSeverity(methodFlags DebugFlag, flag DebugFlag, severity Severity, contextStr string, format string, args ...interface{}) {
	if dm.shouldLogWithMethodContext(methodFlags, flag, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getPathForCombinedFlags(flag)

		if dm.logger != nil {
			// Use structured logging with slog
			attrs := []slog.Attr{
				slog.String("flag", path),
				slog.String("severity", severity.String()),
			}
			if contextStr != "" {
				attrs = append(attrs, slog.String("context", contextStr))
			}

			dm.logger.LogAttrs(nil, dm.severityToSlogLevel(severity), message, attrs...)
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

// LogWithMethodContextAndSeverityAndAttrs writes a debug message using method context flags with severity and structured attributes
func (dm *DebugManager) LogWithMethodContextAndSeverityAndAttrs(methodFlags DebugFlag, flag DebugFlag, severity Severity, contextStr string, message string, attrs []slog.Attr) {
	if dm.shouldLogWithMethodContext(methodFlags, flag, severity) {
		path := dm.getPathForCombinedFlags(flag)

		if dm.logger != nil {
			// Use structured logging with slog
			allAttrs := []slog.Attr{
				slog.String("flag", path),
				slog.String("severity", severity.String()),
			}
			if contextStr != "" {
				allAttrs = append(allAttrs, slog.String("context", contextStr))
			}
			// Add user-provided attributes
			allAttrs = append(allAttrs, attrs...)

			dm.logger.LogAttrs(nil, dm.severityToSlogLevel(severity), message, allAttrs...)
		} else {
			// Use traditional logging
			if contextStr != "" {
				fmt.Fprintf(os.Stderr, "%s [%s] %s: %s", severity.String(), path, contextStr, message)
			} else {
				fmt.Fprintf(os.Stderr, "%s [%s]: %s", severity.String(), path, message)
			}
			// Print structured attributes in traditional format
			if len(attrs) > 0 {
				fmt.Fprintf(os.Stderr, " {")
				for i, attr := range attrs {
					if i > 0 {
						fmt.Fprintf(os.Stderr, ", ")
					}
					fmt.Fprintf(os.Stderr, "%s=%v", attr.Key, attr.Value.Any())
				}
				fmt.Fprintf(os.Stderr, "}")
			}
			fmt.Fprintf(os.Stderr, "\n")
		}
	}
}

// shouldLog determines if a message should be logged based on flag and severity
func (dm *DebugManager) shouldLog(methodFlags DebugFlag, flag DebugFlag, severity Severity) bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Check if the current flag is enabled
	if dm.enabledFlags.HasFlag(flag) {
		// Check severity filters
		path := dm.getPath(flag)
		if dm.shouldLogWithPathSeverity(path, severity) {
			return true
		}
		if len(dm.pathSeverityFilters) > 0 {
			return false
		}
		return severity >= dm.globalSeverityFilter.MinSeverity
	}

	// Check if any method context flags are enabled (inheritance)
	if !methodFlags.IsZero() && dm.enabledFlags.HasFlag(methodFlags) {
		// Check severity filters
		path := dm.getPath(flag)
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

// shouldLogWithMethodContext determines if a message should be logged using method context
func (dm *DebugManager) shouldLogWithMethodContext(methodFlags DebugFlag, flag DebugFlag, severity Severity) bool {
	return dm.shouldLog(methodFlags, flag, severity)
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

// getPath returns the path string for the given flag
func (dm *DebugManager) getPath(flag DebugFlag) string {
	// Search through flag definitions to find a matching flag
	for _, def := range dm.flagDefinitions {
		if flag.HasFlag(def.Flag) {
			return def.Path
		}
	}
	return "unknown"
}

// getPathForCombinedFlags returns the path string for combined flags
func (dm *DebugManager) getPathForCombinedFlags(combinedFlags DebugFlag) string {
	// For combined flags, find the first matching flag and return its path
	for _, def := range dm.flagDefinitions {
		if combinedFlags.HasFlag(def.Flag) {
			return def.Path
		}
	}

	return "unknown"
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
