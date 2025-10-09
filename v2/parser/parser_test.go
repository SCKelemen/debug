package parser

import (
	"testing"

	debug "github.com/SCKelemen/debug"
)

func TestV2Parser(t *testing.T) {
	// Define test flags
	flagMap := map[string]debug.DebugFlag{
		"http.request":    1 << 0,
		"http.response":   1 << 1,
		"db.query":        1 << 2,
		"api.v1.auth.login": 1 << 3,
		"api.v1.auth.logout": 1 << 4,
		"api.v2.auth.login": 1 << 5,
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

		expected := debug.DebugFlag(1<<0 & 1<<1 & 1<<2) // All three flags ANDed = 0
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
		expected := debug.DebugFlag(1<<0) // Only http.request (since http.response & db.query = 0)
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
}

func TestV2ParserGlobMatching(t *testing.T) {
	// Test glob matching through the public API
	flagMap := map[string]debug.DebugFlag{
		"http.request":    1 << 0,
		"http.response":   1 << 1,
		"db.query":        1 << 2,
		"api.v1.auth.login": 1 << 3,
		"api.v1.auth.logout": 1 << 4,
		"api.v2.auth.login": 1 << 5,
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