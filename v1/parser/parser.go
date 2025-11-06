package parser

import (
	"fmt"
	"path/filepath"
	"strings"

	debug "github.com/SCKelemen/debug"
)

// Parser implements FlagParser for simple comma-separated flag strings
type Parser struct{}

// NewParser creates a new parser
func NewParser() debug.FlagParser {
	return &Parser{}
}

// ParseFlags parses comma-separated flag strings (V1 - simple configuration)
func (p *Parser) ParseFlags(flags string, flagMap map[string]debug.DebugFlag, pathMap interface{}) (debug.DebugFlag, []debug.PathSeverityFilter, error) {
	var enabledFlags debug.DebugFlag // nil is equivalent to empty flags
	var pathSeverityFilters []debug.PathSeverityFilter

	// Parse comma-separated flags
	flagNames := strings.Split(flags, ",")
	for _, flagName := range flagNames {
		flagName = strings.TrimSpace(flagName)
		if flagName == "" {
			continue
		}

		// Check for severity filter syntax (e.g., "path:SEVERITY")
		path, severityFilter, err := p.parseFlagWithSeverity(flagName)
		if err != nil {
			return nil, nil, err
		}

		if severityFilter != nil {
			// This is a path with severity filter
			pathSeverityFilters = append(pathSeverityFilters, debug.PathSeverityFilter{
				Pattern: path,
				Filter:  *severityFilter,
			})
		} else {
			// This is a regular flag or glob pattern
			if err := p.enableFlagsForPattern(path, flagMap, &enabledFlags); err != nil {
				return nil, nil, err
			}
		}
	}

	return enabledFlags, pathSeverityFilters, nil
}

// parseFlagWithSeverity parses a flag string that may contain severity filtering
func (p *Parser) parseFlagWithSeverity(flagStr string) (string, *debug.SeverityFilter, error) {
	parts := strings.SplitN(flagStr, ":", 2)
	if len(parts) != 2 {
		// No severity filter, return the flag as-is
		return flagStr, nil, nil
	}

	path := strings.TrimSpace(parts[0])
	severityStr := strings.TrimSpace(parts[1])

	if path == "" || severityStr == "" {
		return "", nil, fmt.Errorf("invalid flag format: %s", flagStr)
	}

	severityFilter, err := p.parseSeverityFilter(severityStr)
	if err != nil {
		return "", nil, err
	}

	return path, severityFilter, nil
}

// parseSeverityFilter parses a severity filter string
func (p *Parser) parseSeverityFilter(severityStr string) (*debug.SeverityFilter, error) {
	// Handle multiple severities with | (e.g., "ERROR|INFO")
	if strings.Contains(severityStr, "|") {
		severities := make(map[debug.Severity]bool)
		parts := strings.Split(severityStr, "|")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			// Remove parentheses if present (e.g., "(ERROR|INFO)" -> "ERROR|INFO")
			part = strings.Trim(part, "()")
			severity, err := p.parseSeverity(part)
			if err != nil {
				return nil, err
			}
			severities[severity] = true
		}
		return &debug.SeverityFilter{
			Type:       debug.SeverityFilterSpecific,
			Severities: severities,
		}, nil
	}

	// Handle minimum severity with + (e.g., "+WARN" or "WARN+")
	if strings.HasPrefix(severityStr, "+") || strings.HasSuffix(severityStr, "+") {
		severityStr = strings.Trim(severityStr, "+")
		severity, err := p.parseSeverity(severityStr)
		if err != nil {
			return nil, err
		}
		return &debug.SeverityFilter{
			Type:        debug.SeverityFilterMin,
			MinSeverity: severity,
		}, nil
	}

	// Handle single severity
	severity, err := p.parseSeverity(severityStr)
	if err != nil {
		return nil, err
	}
	return &debug.SeverityFilter{
		Type:       debug.SeverityFilterSpecific,
		Severities: map[debug.Severity]bool{severity: true},
	}, nil
}

// parseSeverity converts a string to a Severity
func (p *Parser) parseSeverity(severityStr string) (debug.Severity, error) {
	switch strings.ToUpper(severityStr) {
	case "TRACE":
		return debug.SeverityTrace, nil
	case "DEBUG":
		return debug.SeverityDebug, nil
	case "INFO":
		return debug.SeverityInfo, nil
	case "WARN", "WARNING":
		return debug.SeverityWarning, nil
	case "ERROR":
		return debug.SeverityError, nil
	case "FATAL":
		return debug.SeverityFatal, nil
	default:
		return debug.SeverityDebug, fmt.Errorf("unknown severity level: %s", severityStr)
	}
}

// enableFlagsForPattern enables flags matching the given pattern
func (p *Parser) enableFlagsForPattern(pattern string, flagMap map[string]debug.DebugFlag, enabledFlags *debug.DebugFlag) error {
	// Check if it's a direct flag name
	if flag, exists := flagMap[pattern]; exists {
		if *enabledFlags == nil {
			*enabledFlags = flag
		} else {
			*enabledFlags = (*enabledFlags).Or(flag)
		}
		return nil
	}

	// Check if it's a glob pattern - iterate through flagMap since pathMap can't use slice keys
	matched := false
	for flagName, flag := range flagMap {
		if p.matchesGlob(flagName, pattern) {
			if *enabledFlags == nil {
				*enabledFlags = flag
			} else {
				*enabledFlags = (*enabledFlags).Or(flag)
			}
			matched = true
		}
	}

	if !matched {
		return fmt.Errorf("no flags found matching pattern: %s", pattern)
	}

	return nil
}

// matchesGlob checks if a path matches a glob pattern
func (p *Parser) matchesGlob(path, pattern string) bool {
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
