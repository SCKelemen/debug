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

// SeverityFilter represents different types of severity filtering
type SeverityFilter struct {
	Type        SeverityFilterType
	Severities  map[Severity]bool // For specific severities
	MinSeverity Severity          // For minimum severity
}

type SeverityFilterType int

const (
	SeverityFilterAll      SeverityFilterType = iota // Show all severities
	SeverityFilterMin                                // Show minimum severity and above
	SeverityFilterSpecific                           // Show only specific severities
)

// ExpressionNode represents a node in the logical expression AST
type ExpressionNode struct {
	Type     NodeType
	Value    string
	Children []*ExpressionNode
}

type NodeType int

const (
	NodeFlag  NodeType = iota // A flag or glob pattern
	NodeAnd                   // AND operation
	NodeOr                    // OR operation
	NodeNot                   // NOT operation
	NodeGroup                 // Parentheses grouping
)

// DebugManager manages debug flags and output (V2 - with logical expressions)
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

// NewDebugManager creates a new V2 debug manager (with logical expressions)
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
		useSlog:             false,         // Default to traditional logging
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

// SetFlags sets the debug flags from a string (V2 - supports logical expressions)
func (dm *DebugManager) SetFlags(flags string) error {
	if flags == "" {
		return nil
	}

	// Clear existing path severity filters
	dm.pathSeverityFilters = []PathSeverityFilter{}

	// Check if this is a logical expression (contains logical operators)
	if strings.ContainsAny(flags, "&|!()") {
		return dm.setFlagsV2(flags)
	}

	// V1 compatibility: Parse comma-separated flags
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

		// Handle recursive glob
		if path == "**" {
			dm.flags = ^DebugFlag(0) // Set all bits
			if severityFilter != nil {
				dm.pathSeverityFilters = append(dm.pathSeverityFilters, PathSeverityFilter{
					Pattern: "**",
					Filter:  *severityFilter,
				})
			}
			return nil
		}

		// Check if it's a glob pattern
		if strings.Contains(path, "*") {
			// Enable all flags matching this pattern
			for flag, flagPath := range dm.pathMap {
				if dm.matchesGlob(flagPath, path) {
					dm.flags |= flag
				}
			}
		} else {
			// Exact flag match
			if flag, exists := dm.flagMap[path]; exists {
				dm.flags |= flag
			} else {
				return fmt.Errorf("unknown flag: %s", path)
			}
		}

		// Add severity filter if specified
		if severityFilter != nil {
			flag := dm.flagMap[path]
			flagPath := dm.pathMap[flag]
			dm.pathSeverityFilters = append(dm.pathSeverityFilters, PathSeverityFilter{
				Pattern: flagPath,
				Filter:  *severityFilter,
			})
		}
	}

	return nil
}

// setFlagsV2 handles V2 logical expression parsing
func (dm *DebugManager) setFlagsV2(flags string) error {
	// Parse the logical expression
	node, err := dm.parseLogicalExpression(flags)
	if err != nil {
		return fmt.Errorf("failed to parse logical expression: %v", err)
	}

	// Evaluate the expression to determine which flags should be enabled
	enabledFlags, err := dm.evaluateExpressionToFlags(node)
	if err != nil {
		return fmt.Errorf("failed to evaluate logical expression: %v", err)
	}

	// Set the enabled flags
	dm.flags = enabledFlags
	return nil
}

// parseLogicalExpression parses a logical expression string into an AST
func (dm *DebugManager) parseLogicalExpression(expr string) (*ExpressionNode, error) {
	expr = strings.ReplaceAll(expr, " ", "")
	if expr == "" {
		return nil, fmt.Errorf("empty expression")
	}

	return dm.parseOrExpression(expr)
}

// parseOrExpression parses OR expressions (lowest precedence)
func (dm *DebugManager) parseOrExpression(expr string) (*ExpressionNode, error) {
	orPos := dm.findOperatorLeftToRight(expr, "|")
	if orPos == -1 {
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
	andPos := dm.findOperatorLeftToRight(expr, "&")
	if andPos == -1 {
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

// parseNotExpression parses NOT expressions (high precedence)
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

// parsePrimaryExpression parses primary expressions (flags, groups)
func (dm *DebugManager) parsePrimaryExpression(expr string) (*ExpressionNode, error) {
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		// Group expression
		inner := expr[1 : len(expr)-1]
		innerNode, err := dm.parseOrExpression(inner)
		if err != nil {
			return nil, err
		}
		return &ExpressionNode{
			Type:     NodeGroup,
			Children: []*ExpressionNode{innerNode},
		}, nil
	}

	// Single flag or glob pattern
	return &ExpressionNode{
		Type:  NodeFlag,
		Value: expr,
	}, nil
}

// findOperatorLeftToRight finds the position of an operator, respecting parentheses
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

// evaluateExpressionToFlags evaluates a logical expression and returns the flags that should be enabled
func (dm *DebugManager) evaluateExpressionToFlags(node *ExpressionNode) (DebugFlag, error) {
	switch node.Type {
	case NodeFlag:
		// Single flag - check if it exists and return it
		if flag, exists := dm.flagMap[node.Value]; exists {
			return flag, nil
		}
		// If flag doesn't exist, check if it's a glob pattern
		return dm.evaluateGlobPattern(node.Value)
	case NodeAnd:
		if len(node.Children) != 2 {
			return 0, fmt.Errorf("AND node must have exactly 2 children")
		}
		left, err := dm.evaluateExpressionToFlags(node.Children[0])
		if err != nil {
			return 0, err
		}
		right, err := dm.evaluateExpressionToFlags(node.Children[1])
		if err != nil {
			return 0, err
		}
		return left & right, nil
	case NodeOr:
		if len(node.Children) != 2 {
			return 0, fmt.Errorf("OR node must have exactly 2 children")
		}
		left, err := dm.evaluateExpressionToFlags(node.Children[0])
		if err != nil {
			return 0, err
		}
		right, err := dm.evaluateExpressionToFlags(node.Children[1])
		if err != nil {
			return 0, err
		}
		return left | right, nil
	case NodeNot:
		if len(node.Children) != 1 {
			return 0, fmt.Errorf("NOT node must have exactly 1 child")
		}
		// For NOT, we need to get all flags and subtract the specified one
		allFlags := ^DebugFlag(0) // All bits set
		excluded, err := dm.evaluateExpressionToFlags(node.Children[0])
		if err != nil {
			return 0, err
		}
		return allFlags &^ excluded, nil // Clear the excluded flags
	case NodeGroup:
		if len(node.Children) != 1 {
			return 0, fmt.Errorf("GROUP node must have exactly 1 child")
		}
		return dm.evaluateExpressionToFlags(node.Children[0])
	default:
		return 0, fmt.Errorf("unknown node type: %v", node.Type)
	}
}

// evaluateGlobPattern evaluates a glob pattern and returns the matching flags
func (dm *DebugManager) evaluateGlobPattern(pattern string) (DebugFlag, error) {
	var result DebugFlag

	for flag, path := range dm.pathMap {
		if dm.matchesGlob(path, pattern) {
			result |= flag
		}
	}

	return result, nil
}

// parseFlagWithSeverity parses a flag string that may contain severity filtering
func (dm *DebugManager) parseFlagWithSeverity(flagStr string) (string, *SeverityFilter, error) {
	// Check if there's a colon indicating severity filtering
	if !strings.Contains(flagStr, ":") {
		return flagStr, nil, nil
	}

	parts := strings.SplitN(flagStr, ":", 2)
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid flag format: %s", flagStr)
	}

	path := strings.TrimSpace(parts[0])
	severityStr := strings.TrimSpace(parts[1])

	if path == "" || severityStr == "" {
		return "", nil, fmt.Errorf("empty path or severity in: %s", flagStr)
	}

	severityFilter, err := dm.parseSeverityFilter(severityStr)
	if err != nil {
		return "", nil, err
	}

	return path, severityFilter, nil
}

// parseSeverityFilter parses a severity filter string
func (dm *DebugManager) parseSeverityFilter(severityStr string) (*SeverityFilter, error) {
	// Handle minimum severity syntax (+WARN, ERROR+)
	if strings.HasPrefix(severityStr, "+") {
		severity, err := dm.parseSeverity(severityStr[1:])
		if err != nil {
			return nil, err
		}
		return &SeverityFilter{
			Type:        SeverityFilterMin,
			MinSeverity: severity,
		}, nil
	}

	if strings.HasSuffix(severityStr, "+") {
		severity, err := dm.parseSeverity(severityStr[:len(severityStr)-1])
		if err != nil {
			return nil, err
		}
		return &SeverityFilter{
			Type:        SeverityFilterMin,
			MinSeverity: severity,
		}, nil
	}

	// Handle multiple specific severities (ERROR|INFO)
	if strings.Contains(severityStr, "|") {
		parts := strings.Split(severityStr, "|")
		severities := make(map[Severity]bool)
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
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

// parseSeverity parses a severity string
func (dm *DebugManager) parseSeverity(severityStr string) (Severity, error) {
	switch strings.ToUpper(severityStr) {
	case "TRACE":
		return SeverityTrace, nil
	case "DEBUG":
		return SeverityDebug, nil
	case "INFO":
		return SeverityInfo, nil
	case "WARN", "WARNING":
		return SeverityWarning, nil
	case "ERROR":
		return SeverityError, nil
	case "FATAL":
		return SeverityFatal, nil
	default:
		return SeverityDebug, fmt.Errorf("unknown severity level: %s", severityStr)
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

// shouldLogWithPathSeverity checks if a message should be logged based on path-specific severity filters
func (dm *DebugManager) shouldLogWithPathSeverity(path string, severity Severity) bool {
	for _, filter := range dm.pathSeverityFilters {
		if dm.matchesGlob(path, filter.Pattern) {
			return dm.checkSeverityFilter(severity, filter.Filter)
		}
	}
	return false
}

// checkSeverityFilter checks if a severity passes a severity filter
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
	matched, _ := filepath.Match(pattern, path)
	return matched
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

// Context Management Methods

// PushContext adds a flag to the context stack
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
