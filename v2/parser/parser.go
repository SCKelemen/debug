package parser

import (
	"fmt"
	"path/filepath"
	"strings"

	debug "github.com/SCKelemen/debug"
)

// Parser implements FlagParser for logical expression flag strings
type Parser struct{}

// NewParser creates a new parser
func NewParser() debug.FlagParser {
	return &Parser{}
}

// ParseFlags parses logical expression flag strings (V2 - with logical expressions)
func (p *Parser) ParseFlags(flags string, flagMap map[string]debug.DebugFlag, pathMap map[debug.DebugFlag]string) (debug.DebugFlag, []debug.PathSeverityFilter, error) {
	var enabledFlags debug.DebugFlag
	var pathSeverityFilters []debug.PathSeverityFilter

	// Check if this is a logical expression (contains logical operators)
	if strings.ContainsAny(flags, "&|!()") {
		// Parse as V2 logical expression
		enabledFlags, err := p.parseLogicalExpression(flags, flagMap, pathMap)
		if err != nil {
			return 0, nil, err
		}
		return enabledFlags, pathSeverityFilters, nil
	}

	// V1 compatibility: Parse comma-separated flags
	flagNames := strings.Split(flags, ",")
	for _, flagName := range flagNames {
		flagName = strings.TrimSpace(flagName)
		if flagName == "" {
			continue
		}

		// Check for severity filter syntax (e.g., "path:SEVERITY")
		path, severityFilter, err := p.parseFlagWithSeverity(flagName)
		if err != nil {
			return 0, nil, err
		}

		if severityFilter != nil {
			// This is a path with severity filter
			pathSeverityFilters = append(pathSeverityFilters, debug.PathSeverityFilter{
				Pattern: path,
				Filter:  *severityFilter,
			})
		} else {
			// This is a regular flag or glob pattern
			if err := p.enableFlagsForPattern(path, flagMap, pathMap, &enabledFlags); err != nil {
				return 0, nil, err
			}
		}
	}

	return enabledFlags, pathSeverityFilters, nil
}

// ExpressionNode represents a node in the logical expression AST
type ExpressionNode struct {
	Type     NodeType
	Value    string
	Children []*ExpressionNode
}

// NodeType represents the type of expression node
type NodeType int

const (
	NodeFlag  NodeType = iota // Flag name
	NodeAnd                   // AND operation
	NodeOr                    // OR operation
	NodeNot                   // NOT operation
	NodeGroup                 // Parentheses grouping
)

// parseLogicalExpression parses a logical expression and returns enabled flags
func (p *Parser) parseLogicalExpression(expr string, flagMap map[string]debug.DebugFlag, pathMap map[debug.DebugFlag]string) (debug.DebugFlag, error) {
	// Parse V2 logical expression
	node, err := p.parseV2Expression(strings.TrimSpace(expr))
	if err != nil {
		return 0, err
	}

	// Evaluate the expression
	return p.evaluateExpression(node, flagMap, pathMap)
}

// parseV1Expression parses comma-separated flags into an OR expression
func (p *Parser) parseV1Expression(expr string, flagMap map[string]debug.DebugFlag, pathMap map[debug.DebugFlag]string) (debug.DebugFlag, error) {
	var enabledFlags debug.DebugFlag
	flagNames := strings.Split(expr, ",")

	for _, flagName := range flagNames {
		flagName = strings.TrimSpace(flagName)
		if flagName == "" {
			continue
		}

		if err := p.enableFlagsForPattern(flagName, flagMap, pathMap, &enabledFlags); err != nil {
			return 0, err
		}
	}

	return enabledFlags, nil
}

// parseV2Expression parses a V2 logical expression
func (p *Parser) parseV2Expression(expr string) (*ExpressionNode, error) {
	// Parse OR expressions (lowest precedence)
	return p.parseOrExpression(expr)
}

// parseOrExpression parses OR expressions
func (p *Parser) parseOrExpression(expr string) (*ExpressionNode, error) {
	// Find the rightmost OR operator (right associativity)
	pos := p.findOperatorRightToLeft(expr, "|")
	if pos == -1 {
		return p.parseAndExpression(expr)
	}

	left, err := p.parseOrExpression(expr[:pos])
	if err != nil {
		return nil, err
	}

	right, err := p.parseAndExpression(expr[pos+1:])
	if err != nil {
		return nil, err
	}

	return &ExpressionNode{
		Type:     NodeOr,
		Children: []*ExpressionNode{left, right},
	}, nil
}

// parseAndExpression parses AND expressions
func (p *Parser) parseAndExpression(expr string) (*ExpressionNode, error) {
	// Find the rightmost AND operator (right associativity)
	pos := p.findOperatorRightToLeft(expr, "&")
	if pos == -1 {
		return p.parseNotExpression(expr)
	}

	left, err := p.parseAndExpression(expr[:pos])
	if err != nil {
		return nil, err
	}

	right, err := p.parseNotExpression(expr[pos+1:])
	if err != nil {
		return nil, err
	}

	return &ExpressionNode{
		Type:     NodeAnd,
		Children: []*ExpressionNode{left, right},
	}, nil
}

// parseNotExpression parses NOT expressions
func (p *Parser) parseNotExpression(expr string) (*ExpressionNode, error) {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "!") {
		child, err := p.parseNotExpression(expr[1:])
		if err != nil {
			return nil, err
		}
		return &ExpressionNode{
			Type:     NodeNot,
			Children: []*ExpressionNode{child},
		}, nil
	}

	return p.parsePrimaryExpression(expr)
}

// parsePrimaryExpression parses primary expressions (flags and parentheses)
func (p *Parser) parsePrimaryExpression(expr string) (*ExpressionNode, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("empty expression")
	}

	// Handle parentheses
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		// Find matching closing parenthesis
		level := 0
		for i, char := range expr {
			if char == '(' {
				level++
			} else if char == ')' {
				level--
				if level == 0 && i == len(expr)-1 {
					// Found matching closing parenthesis
					inner, err := p.parseV2Expression(expr[1 : len(expr)-1])
					if err != nil {
						return nil, err
					}
					return &ExpressionNode{
						Type:     NodeGroup,
						Children: []*ExpressionNode{inner},
					}, nil
				}
			}
		}
	}

	// It's a flag name
	return &ExpressionNode{
		Type:  NodeFlag,
		Value: expr,
	}, nil
}

// findOperatorRightToLeft finds the rightmost occurrence of an operator
func (p *Parser) findOperatorRightToLeft(expr, op string) int {
	level := 0
	for i := len(expr) - 1; i >= 0; i-- {
		char := expr[i]
		if char == ')' {
			level++
		} else if char == '(' {
			level--
		} else if level == 0 && string(char) == op {
			return i
		}
	}
	return -1
}

// evaluateExpression evaluates the expression AST and returns enabled flags
func (p *Parser) evaluateExpression(node *ExpressionNode, flagMap map[string]debug.DebugFlag, pathMap map[debug.DebugFlag]string) (debug.DebugFlag, error) {
	switch node.Type {
	case NodeFlag:
		return p.evaluateFlag(node.Value, flagMap, pathMap)
	case NodeOr:
		if len(node.Children) != 2 {
			return 0, fmt.Errorf("OR node must have exactly 2 children")
		}
		left, err := p.evaluateExpression(node.Children[0], flagMap, pathMap)
		if err != nil {
			return 0, err
		}
		right, err := p.evaluateExpression(node.Children[1], flagMap, pathMap)
		if err != nil {
			return 0, err
		}
		return left | right, nil
	case NodeAnd:
		if len(node.Children) != 2 {
			return 0, fmt.Errorf("AND node must have exactly 2 children")
		}
		left, err := p.evaluateExpression(node.Children[0], flagMap, pathMap)
		if err != nil {
			return 0, err
		}
		right, err := p.evaluateExpression(node.Children[1], flagMap, pathMap)
		if err != nil {
			return 0, err
		}
		return left & right, nil
	case NodeNot:
		if len(node.Children) != 1 {
			return 0, fmt.Errorf("NOT node must have exactly 1 child")
		}
		child, err := p.evaluateExpression(node.Children[0], flagMap, pathMap)
		if err != nil {
			return 0, err
		}
		// NOT operation: return all flags except the child flags
		var allFlags debug.DebugFlag
		for _, flag := range flagMap {
			allFlags |= flag
		}
		return allFlags &^ child, nil
	case NodeGroup:
		if len(node.Children) != 1 {
			return 0, fmt.Errorf("GROUP node must have exactly 1 child")
		}
		return p.evaluateExpression(node.Children[0], flagMap, pathMap)
	default:
		return 0, fmt.Errorf("unknown node type: %v", node.Type)
	}
}

// evaluateFlag evaluates a single flag or glob pattern
func (p *Parser) evaluateFlag(flagName string, flagMap map[string]debug.DebugFlag, pathMap map[debug.DebugFlag]string) (debug.DebugFlag, error) {
	var enabledFlags debug.DebugFlag
	if err := p.enableFlagsForPattern(flagName, flagMap, pathMap, &enabledFlags); err != nil {
		return 0, err
	}
	return enabledFlags, nil
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
func (p *Parser) enableFlagsForPattern(pattern string, flagMap map[string]debug.DebugFlag, pathMap map[debug.DebugFlag]string, enabledFlags *debug.DebugFlag) error {
	// Check if it's a direct flag name
	if flag, exists := flagMap[pattern]; exists {
		*enabledFlags |= flag
		return nil
	}

	// Check if it's a glob pattern
	matched := false
	for flag, path := range pathMap {
		if p.matchesGlob(path, pattern) {
			*enabledFlags |= flag
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
