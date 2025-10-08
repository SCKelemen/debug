package debug

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// DebugFlag represents a single debug flag
type DebugFlag uint64

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

// String returns the string representation of a severity level
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

// DebugEntry represents a debug entry with path, severity, and message
type DebugEntry struct {
	Path     string
	Severity Severity
	Message  string
	Context  string
}

// FlagDefinition represents a debug flag with its name and path
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

// SeverityFilter represents how severity filtering should work
type SeverityFilter struct {
	Type        SeverityFilterType
	Severities  map[Severity]bool // For specific severities
	MinSeverity Severity          // For minimum severity
}

// SeverityFilterType represents the type of severity filtering
type SeverityFilterType int

const (
	SeverityFilterAll      SeverityFilterType = iota // Show all severities
	SeverityFilterMin                                // Show minimum severity and above
	SeverityFilterSpecific                           // Show only specific severities
)

// DebugManager manages debug flags and output
type DebugManager struct {
	flags               DebugFlag
	severityFilter      Severity
	pathFilters         []string
	pathSeverityFilters []PathSeverityFilter
	globEnabled         bool
	flagMap             map[string]DebugFlag
	pathMap             map[DebugFlag]string
	allFlags            []DebugFlag
	logger              *slog.Logger
	useSlog             bool
	contextStack        []DebugFlag // Stack for hierarchical context
}

// NewDebugManager creates a new debug manager
func NewDebugManager() *DebugManager {
	return &DebugManager{
		flags:               0,
		severityFilter:      SeverityTrace, // Show all by default
		pathFilters:         []string{},
		pathSeverityFilters: []PathSeverityFilter{},
		globEnabled:         true,
		flagMap:             make(map[string]DebugFlag),
		pathMap:             make(map[DebugFlag]string),
		allFlags:            []DebugFlag{},
		logger:              slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		useSlog:             false, // Default to traditional logging
		contextStack:        []DebugFlag{}, // Initialize empty context stack
	}
}

// RegisterFlags registers debug flags with the manager
func (dm *DebugManager) RegisterFlags(definitions []FlagDefinition) {
	for _, def := range definitions {
		dm.flagMap[def.Name] = def.Flag
		dm.pathMap[def.Flag] = def.Path
		dm.allFlags = append(dm.allFlags, def.Flag)
	}
}

// SetFlags sets the debug flags from a string with enhanced pattern matching
func (dm *DebugManager) SetFlags(flags string) error {
	if flags == "" {
		return nil
	}

	// Clear existing path severity filters
	dm.pathSeverityFilters = []PathSeverityFilter{}

	// Parse comma-separated flags
	flagNames := strings.Split(flags, ",")
	for _, flagName := range flagNames {
		flagName = strings.TrimSpace(flagName)
		if flagName == "" {
			continue
		}

		// Check if this flag has a severity filter
		path, severityFilter, err := dm.parseFlagWithSeverity(flagName)
		if err != nil {
			return err
		}

		// Handle special cases
		if path == "all" || path == "*" {
			dm.flags = ^DebugFlag(0) // Set all bits
			if severityFilter != nil {
				dm.pathSeverityFilters = append(dm.pathSeverityFilters, PathSeverityFilter{
					Pattern: "*",
					Filter:  *severityFilter,
				})
			}
			return nil
		}

		// Handle glob patterns
		if dm.globEnabled && (strings.Contains(path, "*") || strings.Contains(path, "**")) {
			dm.pathFilters = append(dm.pathFilters, path)
			// Enable all flags that match the pattern
			dm.enableFlagsMatchingPattern(path)
			if severityFilter != nil {
				dm.pathSeverityFilters = append(dm.pathSeverityFilters, PathSeverityFilter{
					Pattern: path,
					Filter:  *severityFilter,
				})
			}
			continue
		}

		// Map flag names to flags
		flag, exists := dm.flagMap[path]
		if !exists {
			return fmt.Errorf("unknown debug flag: %s", path)
		}

		dm.flags |= flag
		if severityFilter != nil {
			flagPath := dm.pathMap[flag]
			dm.pathSeverityFilters = append(dm.pathSeverityFilters, PathSeverityFilter{
				Pattern: flagPath,
				Filter:  *severityFilter,
			})
		}
	}

	return nil
}

// parseFlagWithSeverity parses a flag string that may contain severity filtering
// Returns: path, severityFilter, error
func (dm *DebugManager) parseFlagWithSeverity(flagStr string) (string, *SeverityFilter, error) {
	// Check if there's a colon indicating severity filtering
	parts := strings.SplitN(flagStr, ":", 2)
	if len(parts) == 1 {
		// No severity filter
		return parts[0], nil, nil
	}

	path := parts[0]
	severityStr := parts[1]

	// Parse severity filter
	severityFilter, err := dm.parseSeverityFilter(severityStr)
	if err != nil {
		return "", nil, fmt.Errorf("invalid severity filter '%s' for path '%s': %v", severityStr, path, err)
	}

	return path, severityFilter, nil
}

// parseSeverityFilter parses a severity filter string
func (dm *DebugManager) parseSeverityFilter(severityStr string) (*SeverityFilter, error) {
	severityStr = strings.TrimSpace(severityStr)

	// Handle + prefix (e.g., +WARN means WARN and above)
	if strings.HasPrefix(severityStr, "+") {
		severityStr = severityStr[1:]
		severity, err := dm.parseSeverity(severityStr)
		if err != nil {
			return nil, err
		}
		return &SeverityFilter{
			Type:        SeverityFilterMin,
			MinSeverity: severity,
		}, nil
	}

	// Handle + suffix (e.g., WARN+ means WARN and above)
	if strings.HasSuffix(severityStr, "+") {
		severityStr = severityStr[:len(severityStr)-1]
		severity, err := dm.parseSeverity(severityStr)
		if err != nil {
			return nil, err
		}
		return &SeverityFilter{
			Type:        SeverityFilterMin,
			MinSeverity: severity,
		}, nil
	}

	// Handle multiple severities separated by | (e.g., ERROR|INFO)
	if strings.Contains(severityStr, "|") {
		severityParts := strings.Split(severityStr, "|")
		severities := make(map[Severity]bool)
		for _, part := range severityParts {
			part = strings.TrimSpace(part)
			severity, err := dm.parseSeverity(part)
			if err != nil {
				return nil, err
			}
			severities[severity] = true
		}
		return &SeverityFilter{
			Type:       SeverityFilterSpecific,
			Severities: severities,
		}, nil
	}

	// Single severity
	severity, err := dm.parseSeverity(severityStr)
	if err != nil {
		return nil, err
	}
	return &SeverityFilter{
		Type:       SeverityFilterSpecific,
		Severities: map[Severity]bool{severity: true},
	}, nil
}

// parseSeverity parses a single severity string
func (dm *DebugManager) parseSeverity(severityStr string) (Severity, error) {
	switch strings.ToUpper(severityStr) {
	case "TRACE":
		return SeverityTrace, nil
	case "DEBUG":
		return SeverityDebug, nil
	case "INFO":
		return SeverityInfo, nil
	case "WARNING", "WARN":
		return SeverityWarning, nil
	case "ERROR":
		return SeverityError, nil
	case "FATAL":
		return SeverityFatal, nil
	default:
		return SeverityTrace, fmt.Errorf("unknown severity: %s", severityStr)
	}
}

// SetSeverityFilter sets the minimum severity level to show
func (dm *DebugManager) SetSeverityFilter(severity Severity) {
	dm.severityFilter = severity
}

// SetSeverityFilterFromString sets the severity filter from a string
func (dm *DebugManager) SetSeverityFilterFromString(severity string) error {
	switch strings.ToLower(severity) {
	case "trace":
		dm.severityFilter = SeverityTrace
	case "debug":
		dm.severityFilter = SeverityDebug
	case "info":
		dm.severityFilter = SeverityInfo
	case "warning", "warn":
		dm.severityFilter = SeverityWarning
	case "error":
		dm.severityFilter = SeverityError
	case "fatal":
		dm.severityFilter = SeverityFatal
	default:
		return fmt.Errorf("unknown severity level: %s", severity)
	}
	return nil
}

// SetPathFilters sets path filters for glob pattern matching
func (dm *DebugManager) SetPathFilters(filters []string) {
	dm.pathFilters = filters
}

// EnableGlob enables or disables glob pattern matching
func (dm *DebugManager) EnableGlob(enabled bool) {
	dm.globEnabled = enabled
}

// enableFlagsMatchingPattern enables all flags that match a glob pattern
func (dm *DebugManager) enableFlagsMatchingPattern(pattern string) {
	for _, flag := range dm.allFlags {
		path := dm.pathMap[flag]
		if dm.matchesGlob(path, pattern) {
			dm.flags |= flag
		}
	}
}

// IsEnabled checks if a debug flag is enabled
func (dm *DebugManager) IsEnabled(flag DebugFlag) bool {
	return dm.flags&flag != 0
}

// IsEnabledByName checks if a flag is enabled by name
func (dm *DebugManager) IsEnabledByName(name string) bool {
	if flag, exists := dm.flagMap[name]; exists {
		return dm.IsEnabled(flag)
	}
	return false
}

// Log writes a debug message if the flag is enabled
func (dm *DebugManager) Log(flag DebugFlag, format string, args ...interface{}) {
	dm.LogWithSeverity(flag, SeverityDebug, "", format, args...)
}

// LogWithContext writes a debug message with additional context
func (dm *DebugManager) LogWithContext(flag DebugFlag, context string, format string, args ...interface{}) {
	dm.LogWithSeverity(flag, SeverityDebug, context, format, args...)
}

// LogWithSeverity writes a debug message with severity level
func (dm *DebugManager) LogWithSeverity(flag DebugFlag, severity Severity, context string, format string, args ...interface{}) {
	if dm.shouldLog(flag, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getPathWithContext(flag)

		if dm.useSlog {
			// Use structured logging with slog
			attrs := []slog.Attr{
				slog.String("flag", path),
				slog.String("severity", severity.String()),
			}
			if context != "" {
				attrs = append(attrs, slog.String("context", context))
			}

			dm.logger.LogAttrs(nil, dm.severityToSlogLevel(severity), message, attrs...)
		} else {
			// Use traditional logging
			if context != "" {
				fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, context, message)
			} else {
				fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
			}
		}
	}
}

// LogWithFlags logs a message if any of the specified flags are enabled
// This allows for more granular control by combining multiple flags
// Example: LogWithFlags(DebugAPIV1AuthLogin|DebugDBQuery, "DB query: %s", query)
func (dm *DebugManager) LogWithFlags(flags DebugFlag, format string, args ...interface{}) {
	dm.LogWithFlagsAndSeverity(flags, SeverityDebug, "", format, args...)
}

// LogWithAnyFlags logs a message if ANY of the specified flags are enabled
// Example: LogWithAnyFlags(DebugAPIV1AuthLogin|DebugHTTPRequest, "Operation in auth login: %s", data)
func (dm *DebugManager) LogWithAnyFlags(flags DebugFlag, format string, args ...interface{}) {
	dm.LogWithAnyFlagsAndSeverity(flags, SeverityDebug, "", format, args...)
}

// LogWithAllFlags logs a message if ALL of the specified flags are enabled
// Example: LogWithAllFlags(DebugAPIV1AuthLogin|DebugDBQuery, "DB query in auth login: %s", query)
func (dm *DebugManager) LogWithAllFlags(flags DebugFlag, format string, args ...interface{}) {
	dm.LogWithAllFlagsAndSeverity(flags, SeverityDebug, "", format, args...)
}

// LogWithFlagsAndContext logs a message with context if any of the specified flags are enabled
func (dm *DebugManager) LogWithFlagsAndContext(flags DebugFlag, context string, format string, args ...interface{}) {
	dm.LogWithFlagsAndSeverity(flags, SeverityDebug, context, format, args...)
}

// LogWithFlagsAndSeverity logs a message with severity if any of the specified flags are enabled
func (dm *DebugManager) LogWithFlagsAndSeverity(flags DebugFlag, severity Severity, context string, format string, args ...interface{}) {
	if dm.shouldLogWithFlags(flags, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getCombinedPath(flags)

		if context != "" {
			fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, context, message)
		} else {
			fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
		}
	}
}

// LogWithAnyFlagsAndContext logs a message with context if ANY of the specified flags are enabled
func (dm *DebugManager) LogWithAnyFlagsAndContext(flags DebugFlag, context string, format string, args ...interface{}) {
	dm.LogWithAnyFlagsAndSeverity(flags, SeverityDebug, context, format, args...)
}

// LogWithAnyFlagsAndSeverity logs a message with severity if ANY of the specified flags are enabled
func (dm *DebugManager) LogWithAnyFlagsAndSeverity(flags DebugFlag, severity Severity, context string, format string, args ...interface{}) {
	if dm.shouldLogWithAnyFlags(flags, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getCombinedPath(flags)

		if context != "" {
			fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, context, message)
		} else {
			fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
		}
	}
}

// LogWithAllFlagsAndContext logs a message with context if ALL of the specified flags are enabled
func (dm *DebugManager) LogWithAllFlagsAndContext(flags DebugFlag, context string, format string, args ...interface{}) {
	dm.LogWithAllFlagsAndSeverity(flags, SeverityDebug, context, format, args...)
}

// LogWithAllFlagsAndSeverity logs a message with severity if ALL of the specified flags are enabled
func (dm *DebugManager) LogWithAllFlagsAndSeverity(flags DebugFlag, severity Severity, context string, format string, args ...interface{}) {
	if dm.shouldLogWithAllFlags(flags, severity) {
		message := fmt.Sprintf(format, args...)
		path := dm.getCombinedPath(flags)

		if context != "" {
			fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, context, message)
		} else {
			fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
		}
	}
}

// Note: LogWithExpression methods were removed as they were based on incorrect understanding.
// Logical expressions should only be used for flag configuration, not for logging calls.
// Use exact flags in code and logical expressions only in SetFlags() for user convenience.

// LogWithPath writes a debug message with a specific path
func (dm *DebugManager) LogWithPath(path string, severity Severity, context string, format string, args ...interface{}) {
	if dm.shouldLogPath(path, severity) {
		message := fmt.Sprintf(format, args...)

		if context != "" {
			fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, context, message)
		} else {
			fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
		}
	}
}

// shouldLog determines if a message should be logged based on flag and severity
func (dm *DebugManager) shouldLog(flag DebugFlag, severity Severity) bool {
	// Combine the flag with current context
	combinedFlag := flag | dm.GetContext()
	
	// Check if the combined flag (including context) is enabled
	if !dm.IsEnabled(combinedFlag) {
		return false
	}

	path := dm.pathMap[flag]

	// Check if there's a path-specific severity filter for this path
	if dm.shouldLogWithPathSeverity(path, severity) {
		return true
	}

	// If there are path-specific filters but none match this path, don't log
	if len(dm.pathSeverityFilters) > 0 {
		return false
	}

	// Fall back to global severity filter
	if severity < dm.severityFilter {
		return false
	}

	// Check path filters if glob is enabled
	if dm.globEnabled && len(dm.pathFilters) > 0 {
		return dm.matchesPathFilters(path)
	}

	return true
}

// shouldLogWithFlags determines if a message should be logged based on multiple flags and severity
// Returns true if ANY of the specified flags are enabled and pass severity filtering
func (dm *DebugManager) shouldLogWithFlags(flags DebugFlag, severity Severity) bool {
	// Check if any of the flags are enabled
	if (dm.flags & flags) == 0 {
		return false
	}

	// For multi-flag logging, we need to check if at least one flag passes all filters
	// We'll use the first enabled flag's path for severity filtering
	for flag := DebugFlag(1); flag <= flags; flag <<= 1 {
		if (flags&flag) != 0 && (dm.flags&flag) != 0 {
			path := dm.pathMap[flag]

			// Check if there's a path-specific severity filter for this path
			if dm.shouldLogWithPathSeverity(path, severity) {
				return true
			}

			// If there are path-specific filters but none match this path, continue checking other flags
			if len(dm.pathSeverityFilters) > 0 {
				continue
			}

			// Fall back to global severity filter
			if severity >= dm.severityFilter {
				// Check path filters if glob is enabled
				if !dm.globEnabled || len(dm.pathFilters) == 0 || dm.matchesPathFilters(path) {
					return true
				}
			}
		}
	}

	return false
}

// shouldLogWithAnyFlags determines if a message should be logged based on multiple flags and severity
// Returns true if ANY of the specified flags are enabled and pass severity filtering
func (dm *DebugManager) shouldLogWithAnyFlags(flags DebugFlag, severity Severity) bool {
	// Check if any of the flags are enabled
	if (dm.flags & flags) == 0 {
		return false
	}

	// For multi-flag logging, we need to check if at least one flag passes all filters
	// We'll use the first enabled flag's path for severity filtering
	for flag := DebugFlag(1); flag <= flags; flag <<= 1 {
		if (flags&flag) != 0 && (dm.flags&flag) != 0 {
			path := dm.pathMap[flag]

			// Check if there's a path-specific severity filter for this path
			if dm.shouldLogWithPathSeverity(path, severity) {
				return true
			}

			// If there are path-specific filters but none match this path, continue checking other flags
			if len(dm.pathSeverityFilters) > 0 {
				continue
			}

			// Fall back to global severity filter
			if severity >= dm.severityFilter {
				// Check path filters if glob is enabled
				if !dm.globEnabled || len(dm.pathFilters) == 0 || dm.matchesPathFilters(path) {
					return true
				}
			}
		}
	}

	return false
}

// shouldLogWithAllFlags determines if a message should be logged based on multiple flags and severity
// Returns true if ALL of the specified flags are enabled and pass severity filtering
func (dm *DebugManager) shouldLogWithAllFlags(flags DebugFlag, severity Severity) bool {
	// Check if ALL of the flags are enabled
	if (dm.flags & flags) != flags {
		return false
	}

	// For ALL flag logging, we need to check if all flags pass their respective filters
	// We'll use the first flag's path for severity filtering (they should all be similar)
	for flag := DebugFlag(1); flag <= flags; flag <<= 1 {
		if (flags & flag) != 0 {
			path := dm.pathMap[flag]

			// Check if there's a path-specific severity filter for this path
			if dm.shouldLogWithPathSeverity(path, severity) {
				return true
			}

			// If there are path-specific filters but none match this path, continue checking other flags
			if len(dm.pathSeverityFilters) > 0 {
				continue
			}

			// Fall back to global severity filter
			if severity >= dm.severityFilter {
				// Check path filters if glob is enabled
				if !dm.globEnabled || len(dm.pathFilters) == 0 || dm.matchesPathFilters(path) {
					return true
				}
			}
		}
	}

	return false
}

// Note: shouldLogWithExpression was removed as logical expressions should only be used for flag configuration.

// getFirstFlagFromExpression extracts the first flag from an expression node
func (dm *DebugManager) getFirstFlagFromExpression(node *ExpressionNode) string {
	if node.Type == NodeFlag {
		return node.Value
	}

	for _, child := range node.Children {
		if flag := dm.getFirstFlagFromExpression(child); flag != "" {
			return flag
		}
	}

	return ""
}

// getCombinedPath creates a combined path string for multiple flags
func (dm *DebugManager) getCombinedPath(flags DebugFlag) string {
	var paths []string

	for flag := DebugFlag(1); flag <= flags; flag <<= 1 {
		if (flags&flag) != 0 && (dm.flags&flag) != 0 {
			if path, exists := dm.pathMap[flag]; exists {
				paths = append(paths, path)
			}
		}
	}

	if len(paths) == 0 {
		return "unknown"
	}

	if len(paths) == 1 {
		return paths[0]
	}

	// For multiple paths, combine them with "|"
	return strings.Join(paths, "|")
}

// shouldLogPath determines if a message should be logged based on path and severity
func (dm *DebugManager) shouldLogPath(path string, severity Severity) bool {
	// Check path-specific severity filters first
	if dm.shouldLogWithPathSeverity(path, severity) {
		return true
	}

	// Fall back to global severity filter
	if severity < dm.severityFilter {
		return false
	}

	// Check path filters if glob is enabled
	if dm.globEnabled && len(dm.pathFilters) > 0 {
		return dm.matchesPathFilters(path)
	}

	return true
}

// shouldLogWithPathSeverity checks if a message should be logged based on path-specific severity filters
func (dm *DebugManager) shouldLogWithPathSeverity(path string, severity Severity) bool {
	// Check if there are any path-specific severity filters
	if len(dm.pathSeverityFilters) == 0 {
		return false
	}

	// Find matching path severity filters
	for _, pathFilter := range dm.pathSeverityFilters {
		if dm.matchesGlob(path, pathFilter.Pattern) {
			return dm.checkSeverityFilter(severity, pathFilter.Filter)
		}
	}

	return false
}

// checkSeverityFilter checks if a severity matches a severity filter
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

// matchesPathFilters checks if a path matches any of the path filters
func (dm *DebugManager) matchesPathFilters(path string) bool {
	for _, filter := range dm.pathFilters {
		if dm.matchesGlob(path, filter) {
			return true
		}
	}
	return false
}

// matchesGlob checks if a path matches a glob pattern
func (dm *DebugManager) matchesGlob(path, pattern string) bool {
	// Handle special cases
	if pattern == "*" || pattern == "**" {
		return true
	}

	// Convert glob pattern to filepath.Match pattern
	// Replace ** with * for recursive matching
	pattern = strings.ReplaceAll(pattern, "**", "*")

	// Use filepath.Match for glob matching
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		// If pattern is invalid, fall back to simple string matching
		return strings.Contains(path, strings.TrimSuffix(strings.TrimPrefix(pattern, "*"), "*"))
	}

	return matched
}

// GetEnabledFlags returns a list of enabled flag names
func (dm *DebugManager) GetEnabledFlags() []string {
	var enabled []string
	for name, flag := range dm.flagMap {
		if dm.IsEnabled(flag) {
			enabled = append(enabled, name)
		}
	}
	return enabled
}

// GetAvailableFlags returns a list of all available flag names
func (dm *DebugManager) GetAvailableFlags() []string {
	var flags []string
	for name := range dm.flagMap {
		flags = append(flags, name)
	}
	return flags
}

// GetFlagPath returns the hierarchical path for a debug flag
func (dm *DebugManager) GetFlagPath(flag DebugFlag) string {
	if path, exists := dm.pathMap[flag]; exists {
		return path
	}
	return "unknown"
}

// GetFlagName returns the name of a debug flag
func (dm *DebugManager) GetFlagName(flag DebugFlag) string {
	for name, f := range dm.flagMap {
		if f == flag {
			return name
		}
	}
	return "unknown"
}

// ExpressionNode represents a node in the logical expression tree
type ExpressionNode struct {
	Type     NodeType
	Value    string
	Children []*ExpressionNode
}

type NodeType int

const (
	NodeFlag NodeType = iota
	NodeAnd
	NodeOr
	NodeNot
	NodeGroup
)

// parseLogicalExpression parses a logical expression string into an AST
func (dm *DebugManager) parseLogicalExpression(expr string) (*ExpressionNode, error) {
	// Remove whitespace
	expr = strings.ReplaceAll(expr, " ", "")
	if expr == "" {
		return nil, fmt.Errorf("empty expression")
	}

	// Check if this is a simple V1 expression (no logical operators)
	if !strings.ContainsAny(expr, "&|!()") {
		return dm.parseV1Expression(expr)
	}

	// Parse V2 logical expression
	return dm.parseV2Expression(expr)
}

// parseV1Expression parses a simple V1 expression (comma-separated flags)
func (dm *DebugManager) parseV1Expression(expr string) (*ExpressionNode, error) {
	flags := strings.Split(expr, ",")
	if len(flags) == 1 {
		// Single flag
		return &ExpressionNode{Type: NodeFlag, Value: strings.TrimSpace(flags[0])}, nil
	}

	// Multiple flags - create OR expression
	children := make([]*ExpressionNode, len(flags))
	for i, flag := range flags {
		children[i] = &ExpressionNode{Type: NodeFlag, Value: strings.TrimSpace(flag)}
	}
	return &ExpressionNode{Type: NodeOr, Children: children}, nil
}

// parseV2Expression parses a V2 logical expression with operators
func (dm *DebugManager) parseV2Expression(expr string) (*ExpressionNode, error) {
	// Simple recursive descent parser
	return dm.parseOrExpression(expr)
}

// parseOrExpression parses OR expressions (lowest precedence)
func (dm *DebugManager) parseOrExpression(expr string) (*ExpressionNode, error) {
	// Look for OR operators from left to right
	orPos := dm.findOperatorLeftToRight(expr, "|")
	if orPos == -1 {
		// No OR operator found, parse as AND expression
		return dm.parseAndExpression(expr)
	}

	left, err := dm.parseAndExpression(expr[:orPos])
	if err != nil {
		return nil, err
	}

	right, err := dm.parseOrExpression(expr[orPos+1:])
	if err != nil {
		return nil, err
	}

	return &ExpressionNode{
		Type:     NodeOr,
		Children: []*ExpressionNode{left, right},
	}, nil
}

// parseAndExpression parses AND expressions (medium precedence)
func (dm *DebugManager) parseAndExpression(expr string) (*ExpressionNode, error) {
	// Look for AND operators from left to right
	andPos := dm.findOperatorLeftToRight(expr, "&")
	if andPos == -1 {
		// No AND operator found, parse as NOT expression
		return dm.parseNotExpression(expr)
	}

	left, err := dm.parseNotExpression(expr[:andPos])
	if err != nil {
		return nil, err
	}

	right, err := dm.parseAndExpression(expr[andPos+1:])
	if err != nil {
		return nil, err
	}

	return &ExpressionNode{
		Type:     NodeAnd,
		Children: []*ExpressionNode{left, right},
	}, nil
}

// parseNotExpression parses NOT expressions (highest precedence)
func (dm *DebugManager) parseNotExpression(expr string) (*ExpressionNode, error) {
	if strings.HasPrefix(expr, "!") {
		operand, err := dm.parsePrimaryExpression(expr[1:])
		if err != nil {
			return nil, err
		}
		return &ExpressionNode{
			Type:     NodeNot,
			Children: []*ExpressionNode{operand},
		}, nil
	}

	return dm.parsePrimaryExpression(expr)
}

// parsePrimaryExpression parses primary expressions (flags and groups)
func (dm *DebugManager) parsePrimaryExpression(expr string) (*ExpressionNode, error) {
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		// Group expression
		inner := expr[1 : len(expr)-1]
		return dm.parseOrExpression(inner)
	}

	// Single flag
	return &ExpressionNode{Type: NodeFlag, Value: expr}, nil
}

// findOperator finds the position of an operator, respecting parentheses
func (dm *DebugManager) findOperator(expr, op string) int {
	parenCount := 0
	for i := len(expr) - 1; i >= 0; i-- {
		if expr[i] == ')' {
			parenCount++
		} else if expr[i] == '(' {
			parenCount--
		} else if parenCount == 0 && strings.HasPrefix(expr[i:], op) {
			return i
		}
	}
	return -1
}

// findOperatorLeftToRight finds the position of an operator from left to right, respecting parentheses
func (dm *DebugManager) findOperatorLeftToRight(expr, op string) int {
	parenCount := 0
	for i := 0; i < len(expr); i++ {
		if expr[i] == '(' {
			parenCount++
		} else if expr[i] == ')' {
			parenCount--
		} else if parenCount == 0 && strings.HasPrefix(expr[i:], op) {
			return i
		}
	}
	return -1
}

// evaluateExpression evaluates a logical expression against enabled flags
func (dm *DebugManager) evaluateExpression(node *ExpressionNode) (bool, error) {
	switch node.Type {
	case NodeFlag:
		// Check if this flag is enabled
		return dm.isFlagEnabled(node.Value), nil
	case NodeAnd:
		if len(node.Children) != 2 {
			return false, fmt.Errorf("AND node must have exactly 2 children")
		}
		left, err := dm.evaluateExpression(node.Children[0])
		if err != nil {
			return false, err
		}
		right, err := dm.evaluateExpression(node.Children[1])
		if err != nil {
			return false, err
		}
		return left && right, nil
	case NodeOr:
		if len(node.Children) != 2 {
			return false, fmt.Errorf("OR node must have exactly 2 children")
		}
		left, err := dm.evaluateExpression(node.Children[0])
		if err != nil {
			return false, err
		}
		right, err := dm.evaluateExpression(node.Children[1])
		if err != nil {
			return false, err
		}
		return left || right, nil
	case NodeNot:
		if len(node.Children) != 1 {
			return false, fmt.Errorf("NOT node must have exactly 1 child")
		}
		result, err := dm.evaluateExpression(node.Children[0])
		if err != nil {
			return false, err
		}
		return !result, nil
	case NodeGroup:
		if len(node.Children) != 1 {
			return false, fmt.Errorf("GROUP node must have exactly 1 child")
		}
		return dm.evaluateExpression(node.Children[0])
	default:
		return false, fmt.Errorf("unknown node type: %v", node.Type)
	}
}

// isFlagEnabled checks if a flag pattern is enabled
func (dm *DebugManager) isFlagEnabled(flagPattern string) bool {
	// Check for exact match first
	if dm.IsEnabledByName(flagPattern) {
		return true
	}

	// Check for glob pattern match
	for flag, path := range dm.pathMap {
		if dm.IsEnabled(flag) && dm.matchesGlob(path, flagPattern) {
			return true
		}
	}

	return false
}

// Slog Integration Methods

// SetSlogLogger sets a custom slog.Logger for the debug manager
func (dm *DebugManager) SetSlogLogger(logger *slog.Logger) {
	dm.logger = logger
	dm.useSlog = true
}

// EnableSlog enables slog integration with default settings
func (dm *DebugManager) EnableSlog() {
	dm.logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dm.useSlog = true
}

// EnableSlogWithHandler enables slog integration with a custom handler
func (dm *DebugManager) EnableSlogWithHandler(handler slog.Handler) {
	dm.logger = slog.New(handler)
	dm.useSlog = true
}

// DisableSlog disables slog integration and returns to traditional logging
func (dm *DebugManager) DisableSlog() {
	dm.useSlog = false
}

// IsSlogEnabled returns whether slog integration is enabled
func (dm *DebugManager) IsSlogEnabled() bool {
	return dm.useSlog
}

// Context Management Methods

// PushContext adds a flag to the context stack
// This is useful for hierarchical logging where child operations inherit parent context
func (dm *DebugManager) PushContext(flag DebugFlag) {
	dm.contextStack = append(dm.contextStack, flag)
}

// PopContext removes the most recent flag from the context stack
func (dm *DebugManager) PopContext() DebugFlag {
	if len(dm.contextStack) == 0 {
		return 0
	}
	
	lastIndex := len(dm.contextStack) - 1
	flag := dm.contextStack[lastIndex]
	dm.contextStack = dm.contextStack[:lastIndex]
	return flag
}

// GetContext returns the current context (combination of all flags in the stack)
func (dm *DebugManager) GetContext() DebugFlag {
	var context DebugFlag
	for _, flag := range dm.contextStack {
		context |= flag
	}
	return context
}

// ClearContext clears the entire context stack
func (dm *DebugManager) ClearContext() {
	dm.contextStack = []DebugFlag{}
}

// WithContext executes a function with a temporary context
// The context is automatically popped when the function returns
func (dm *DebugManager) WithContext(flag DebugFlag, fn func()) {
	dm.PushContext(flag)
	defer dm.PopContext()
	fn()
}

// getPathWithContext returns the path string including context information
func (dm *DebugManager) getPathWithContext(flag DebugFlag) string {
	path := dm.pathMap[flag]
	if path == "" {
		path = "unknown"
	}
	
	// Add context information if available
	context := dm.GetContext()
	if context != 0 {
		var contextPaths []string
		for _, ctxFlag := range dm.contextStack {
			if ctxPath := dm.pathMap[ctxFlag]; ctxPath != "" {
				contextPaths = append(contextPaths, ctxPath)
			}
		}
		if len(contextPaths) > 0 {
			path = fmt.Sprintf("%s (ctx: %s)", path, strings.Join(contextPaths, " -> "))
		}
	}
	
	return path
}

// severityToSlogLevel converts our Severity to slog.Level
func (dm *DebugManager) severityToSlogLevel(severity Severity) slog.Level {
	switch severity {
	case SeverityTrace:
		return slog.LevelDebug - 1 // Custom level below debug
	case SeverityDebug:
		return slog.LevelDebug
	case SeverityInfo:
		return slog.LevelInfo
	case SeverityWarning:
		return slog.LevelWarn
	case SeverityError:
		return slog.LevelError
	case SeverityFatal:
		return slog.LevelError + 1 // Custom level above error
	default:
		return slog.LevelDebug
	}
}
