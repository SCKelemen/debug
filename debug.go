package debug

import (
	"fmt"
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
	SeverityFilterAll SeverityFilterType = iota // Show all severities
	SeverityFilterMin                            // Show minimum severity and above
	SeverityFilterSpecific                       // Show only specific severities
)

// DebugManager manages debug flags and output
type DebugManager struct {
	flags              DebugFlag
	severityFilter     Severity
	pathFilters        []string
	pathSeverityFilters []PathSeverityFilter
	globEnabled        bool
	flagMap            map[string]DebugFlag
	pathMap            map[DebugFlag]string
	allFlags           []DebugFlag
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
		path := dm.pathMap[flag]

		if context != "" {
			fmt.Fprintf(os.Stderr, "%s [%s] %s: %s\n", severity.String(), path, context, message)
		} else {
			fmt.Fprintf(os.Stderr, "%s [%s]: %s\n", severity.String(), path, message)
		}
	}
}

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
	// Check if flag is enabled
	if !dm.IsEnabled(flag) {
		return false
	}

	path := dm.pathMap[flag]

	// Check path-specific severity filters first
	if len(dm.pathSeverityFilters) > 0 {
		// If there are path-specific filters, only use them
		return dm.shouldLogWithPathSeverity(path, severity)
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
