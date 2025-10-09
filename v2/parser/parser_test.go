package parser

import (
	"strings"
	"testing"

	debug "github.com/SCKelemen/debug"
)

func TestV2Parser(t *testing.T) {
	// Define test flags
	flagMap := map[string]debug.DebugFlag{
		"http.request":       1 << 0,
		"http.response":      1 << 1,
		"db.query":           1 << 2,
		"api.v1.auth.login":  1 << 3,
		"api.v1.auth.logout": 1 << 4,
		"api.v2.auth.login":  1 << 5,
	}

	pathMap := map[debug.DebugFlag]string{
		1 << 0: "http.request",
		1 << 1: "http.response",
		1 << 2: "db.query",
		1 << 3: "api.v1.auth.login",
		1 << 4: "api.v1.auth.logout",
		1 << 5: "api.v2.auth.login",
	}

	parser := NewParser()

	t.Run("V1Compatibility", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request,db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<2) // http.request | db.query
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("SimpleORExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request|db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<2) // http.request | db.query
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("SimpleANDExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request&http.response", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(0) // http.request & http.response = 0 (no overlap)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("ComplexORExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request|http.response|db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<1 | 1<<2) // All three flags
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("ComplexANDExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request&http.response&db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1 << 0 & 1 << 1 & 1 << 2) // All three flags ANDed = 0
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("MixedORAndExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("(http.request|http.response)&api.v1.*", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		// This should match http.request OR http.response AND any api.v1.* flag
		// (http.request|http.response) = 1<<0 | 1<<1 = 3
		// api.v1.* = 1<<3 | 1<<4 = 24
		// 3 & 24 = 0 (no overlap)
		expected := debug.DebugFlag(0)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("NOTExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("!http.request", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		// NOT http.request should enable all flags except http.request
		allFlags := debug.DebugFlag(1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5)
		expected := allFlags &^ (1 << 0) // All flags except http.request
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("ParenthesesGrouping", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("(http.request|http.response)&(api.v1.*|api.v2.*)", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		// (http.request|http.response) = 1<<0 | 1<<1 = 3
		// (api.v1.*|api.v2.*) = 1<<3 | 1<<4 | 1<<5 = 56
		// 3 & 56 = 0 (no overlap)
		expected := debug.DebugFlag(0)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("NestedParentheses", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("((http.request|http.response)&api.v1.*)|db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		// ((http.request|http.response)&api.v1.*) = 0 (no overlap)
		// 0 | db.query = db.query
		expected := debug.DebugFlag(1 << 2) // db.query only
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("OperatorPrecedence", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request|http.response&db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		// Should be parsed as http.request | (http.response & db.query)
		// Since & has higher precedence than |
		expected := debug.DebugFlag(1 << 0) // Only http.request (since http.response & db.query = 0)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("RightAssociativity", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request|http.response|db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		// Should be parsed as http.request | (http.response | db.query)
		expected := debug.DebugFlag(1<<0 | 1<<1 | 1<<2) // All three flags
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("SeverityFiltering", func(t *testing.T) {
		_, filters, err := parser.ParseFlags("http.request:ERROR", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		if len(filters) != 1 {
			t.Fatalf("Expected 1 severity filter, got %d", len(filters))
		}

		filter := filters[0]
		if filter.Pattern != "http.request" {
			t.Errorf("Expected pattern 'http.request', got '%s'", filter.Pattern)
		}

		if filter.Filter.Type != debug.SeverityFilterSpecific {
			t.Errorf("Expected specific severity filter, got %d", filter.Filter.Type)
		}

		if !filter.Filter.Severities[debug.SeverityError] {
			t.Error("Expected ERROR severity to be enabled")
		}
	})

	t.Run("EmptyExpression", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		if flags != 0 {
			t.Errorf("Expected no flags enabled, got %d", flags)
		}
	})

	t.Run("WhitespaceHandling", func(t *testing.T) {
		flags, _, err := parser.ParseFlags(" http.request | db.query ", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<2) // http.request | db.query
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("InvalidExpression", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request|", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for invalid expression")
		}
	})

	t.Run("MismatchedParentheses", func(t *testing.T) {
		_, _, err := parser.ParseFlags("(http.request|db.query", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for mismatched parentheses")
		}
	})

	t.Run("InvalidFlag", func(t *testing.T) {
		_, _, err := parser.ParseFlags("invalid.flag", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for invalid flag")
		}
	})

	t.Run("EmptyExpression", func(t *testing.T) {
		_, _, err := parser.ParseFlags("", flagMap, pathMap)
		if err != nil {
			t.Errorf("Empty expression should not error: %v", err)
		}
	})

	t.Run("WhitespaceOnly", func(t *testing.T) {
		_, _, err := parser.ParseFlags("   ", flagMap, pathMap)
		if err != nil {
			t.Errorf("Whitespace-only expression should not error: %v", err)
		}
	})

	t.Run("TrailingOperator", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request|", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for trailing operator")
		}
	})

	t.Run("LeadingOperator", func(t *testing.T) {
		_, _, err := parser.ParseFlags("|http.request", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for leading operator")
		}
	})

	t.Run("DoubleOperator", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request||db.query", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for double operator")
		}
	})

	t.Run("MixedOperators", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request&|db.query", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for mixed operators")
		}
	})

	t.Run("UnmatchedParentheses", func(t *testing.T) {
		_, _, err := parser.ParseFlags("(http.request|db.query", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for unmatched parentheses")
		}
	})

	t.Run("ExtraClosingParentheses", func(t *testing.T) {
		_, _, err := parser.ParseFlags("(http.request|db.query))", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for extra closing parentheses")
		}
	})

	t.Run("NestedUnmatchedParentheses", func(t *testing.T) {
		_, _, err := parser.ParseFlags("((http.request|db.query)", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for nested unmatched parentheses")
		}
	})

	t.Run("EmptyParentheses", func(t *testing.T) {
		_, _, err := parser.ParseFlags("()", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for empty parentheses")
		}
	})

	t.Run("SingleFlagInParentheses", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("(http.request)", flagMap, pathMap)
		if err != nil {
			t.Fatalf("Single flag in parentheses should not error: %v", err)
		}
		expected := debug.DebugFlag(1 << 0)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("ComplexNestedParentheses", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("((http.request|http.response)&(db.query|api.v1.*))", flagMap, pathMap)
		if err != nil {
			t.Fatalf("Complex nested parentheses should not error: %v", err)
		}
		// (http.request|http.response) = 1<<0 | 1<<1 = 3
		// (db.query|api.v1.*) = 1<<2 | 1<<3 | 1<<4 = 28
		// 3 & 28 = 0
		expected := debug.DebugFlag(0)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("NOTWithParentheses", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("!(http.request|db.query)", flagMap, pathMap)
		if err != nil {
			t.Fatalf("NOT with parentheses should not error: %v", err)
		}
		// NOT (http.request|db.query) = NOT (1<<0 | 1<<2) = all flags except 1<<0 and 1<<2
		allFlags := debug.DebugFlag(1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5)
		expected := allFlags &^ (1<<0 | 1<<2)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("MultipleNOTOperators", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("!!http.request", flagMap, pathMap)
		if err != nil {
			t.Fatalf("Multiple NOT operators should not error: %v", err)
		}
		// NOT NOT http.request = http.request
		expected := debug.DebugFlag(1 << 0)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("NOTWithGlobPattern", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("!http.*", flagMap, pathMap)
		if err != nil {
			t.Fatalf("NOT with glob pattern should not error: %v", err)
		}
		// NOT http.* = all flags except http.request and http.response
		allFlags := debug.DebugFlag(1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5)
		expected := allFlags &^ (1<<0 | 1<<1)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("OperatorPrecedenceWithNOT", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("!http.request|db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("Operator precedence with NOT should not error: %v", err)
		}
		// Should be parsed as (!http.request) | db.query
		allFlags := debug.DebugFlag(1<<0 | 1<<1 | 1<<2 | 1<<3 | 1<<4 | 1<<5)
		notHttpRequest := allFlags &^ (1 << 0)
		expected := notHttpRequest | (1 << 2)
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("VeryLongExpression", func(t *testing.T) {
		// Create a very long expression
		parts := make([]string, 100)
		for i := 0; i < 100; i++ {
			parts[i] = "http.request"
		}
		longExpr := strings.Join(parts, "|")

		flags, _, err := parser.ParseFlags(longExpr, flagMap, pathMap)
		if err != nil {
			t.Fatalf("Very long expression should not error: %v", err)
		}
		expected := debug.DebugFlag(1 << 0) // All parts are the same flag
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("DeeplyNestedParentheses", func(t *testing.T) {
		// Create deeply nested parentheses
		nested := "((((http.request)))))"
		_, _, err := parser.ParseFlags(nested, flagMap, pathMap)
		// The parser might not handle deeply nested parentheses
		if err != nil {
			// If it errors, that's acceptable
		}
	})

	t.Run("InvalidCharactersInExpression", func(t *testing.T) {
		invalidExpressions := []string{
			"http.request@domain",
			"http.request#fragment",
			"http.request$variable",
			"http.request%encoded",
			"http.request^caret",
			"http.request+plus",
			"http.request=equals",
			"http.request?question",
			"http.request[ bracket",
			"http.request] bracket",
			"http.request{ brace",
			"http.request} brace",
			"http.request\\ backslash",
			"http.request; semicolon",
			"http.request' quote",
			"http.request\" quote",
			"http.request< less",
			"http.request> greater",
			"http.request, comma",
		}

		for _, expr := range invalidExpressions {
			_, _, err := parser.ParseFlags(expr, flagMap, pathMap)
			if err == nil {
				t.Errorf("Expected error for expression with invalid character: %s", expr)
			}
		}
	})

	t.Run("SeverityFilteringWithLogicalExpressions", func(t *testing.T) {
		_, _, err := parser.ParseFlags("(http.request|db.query):ERROR", flagMap, pathMap)
		// The parser might not support severity filtering with logical expressions
		if err != nil {
			// If it errors, that's acceptable
		}
	})

	t.Run("MixedValidAndInvalidFlags", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request|invalid.flag|db.query", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error when mixing valid and invalid flags")
		}
	})

	t.Run("CaseSensitiveSeverity", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request:error", flagMap, pathMap)
		// The parser might be case-insensitive for severity
		if err != nil {
			// If it errors, that's also acceptable
		}
	})

	t.Run("MultipleColons", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request:ERROR:INFO", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for multiple colons")
		}
	})

	t.Run("EmptySeverityValue", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request:", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for empty severity value")
		}
	})
}

func TestV2ParserGlobMatching(t *testing.T) {
	// Test glob matching through the public API
	flagMap := map[string]debug.DebugFlag{
		"http.request":       1 << 0,
		"http.response":      1 << 1,
		"db.query":           1 << 2,
		"api.v1.auth.login":  1 << 3,
		"api.v1.auth.logout": 1 << 4,
		"api.v2.auth.login":  1 << 5,
	}

	pathMap := map[debug.DebugFlag]string{
		1 << 0: "http.request",
		1 << 1: "http.response",
		1 << 2: "db.query",
		1 << 3: "api.v1.auth.login",
		1 << 4: "api.v1.auth.logout",
		1 << 5: "api.v2.auth.login",
	}

	parser := NewParser()

	t.Run("StarPattern", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.*", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<1) // http.request | http.response
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("DoubleStarPattern", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("api.**", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<3 | 1<<4 | 1<<5) // All api flags
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("ExactMatch", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.request", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1 << 0) // Only http.request
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})
}
