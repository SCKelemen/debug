package parser

import (
	"testing"

	debug "github.com/SCKelemen/debug"
)

func TestV1Parser(t *testing.T) {
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

	t.Run("SimpleCommaSeparated", func(t *testing.T) {
		flags, filters, err := parser.ParseFlags("http.request,db.query", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<2) // http.request | db.query
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}

		if len(filters) != 0 {
			t.Errorf("Expected no severity filters, got %d", len(filters))
		}
	})

	t.Run("GlobPatterns", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("http.*", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<1) // http.request | http.response
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("RecursiveGlobPatterns", func(t *testing.T) {
		flags, _, err := parser.ParseFlags("api.**", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<3 | 1<<4 | 1<<5) // All api flags
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

	t.Run("MultipleSeverityFiltering", func(t *testing.T) {
		_, filters, err := parser.ParseFlags("http.request:ERROR|INFO", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		if len(filters) != 1 {
			t.Fatalf("Expected 1 severity filter, got %d", len(filters))
		}

		filter := filters[0]
		if !filter.Filter.Severities[debug.SeverityError] {
			t.Error("Expected ERROR severity to be enabled")
		}
		if !filter.Filter.Severities[debug.SeverityInfo] {
			t.Error("Expected INFO severity to be enabled")
		}
	})

	t.Run("MinimumSeverityFiltering", func(t *testing.T) {
		_, filters, err := parser.ParseFlags("http.request:+WARN", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		if len(filters) != 1 {
			t.Fatalf("Expected 1 severity filter, got %d", len(filters))
		}

		filter := filters[0]
		if filter.Filter.Type != debug.SeverityFilterMin {
			t.Errorf("Expected minimum severity filter, got %d", filter.Filter.Type)
		}

		if filter.Filter.MinSeverity != debug.SeverityWarning {
			t.Errorf("Expected minimum severity WARNING, got %d", filter.Filter.MinSeverity)
		}
	})

	t.Run("MixedFlagsAndSeverity", func(t *testing.T) {
		flags, filters, err := parser.ParseFlags("http.request,db.query:ERROR", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1 << 0) // Only http.request
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}

		if len(filters) != 1 {
			t.Fatalf("Expected 1 severity filter, got %d", len(filters))
		}

		filter := filters[0]
		if filter.Pattern != "db.query" {
			t.Errorf("Expected pattern 'db.query', got '%s'", filter.Pattern)
		}
	})

	t.Run("EmptyFlags", func(t *testing.T) {
		flags, filters, err := parser.ParseFlags("", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		if flags != 0 {
			t.Errorf("Expected no flags enabled, got %d", flags)
		}

		if len(filters) != 0 {
			t.Errorf("Expected no severity filters, got %d", len(filters))
		}
	})

	t.Run("WhitespaceHandling", func(t *testing.T) {
		flags, _, err := parser.ParseFlags(" http.request , db.query ", flagMap, pathMap)
		if err != nil {
			t.Fatalf("ParseFlags failed: %v", err)
		}

		expected := debug.DebugFlag(1<<0 | 1<<2) // http.request | db.query
		if flags != expected {
			t.Errorf("Expected flags %d, got %d", expected, flags)
		}
	})

	t.Run("InvalidFlag", func(t *testing.T) {
		_, _, err := parser.ParseFlags("invalid.flag", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for invalid flag")
		}
	})

	t.Run("InvalidSeverity", func(t *testing.T) {
		_, _, err := parser.ParseFlags("http.request:INVALID", flagMap, pathMap)
		if err == nil {
			t.Error("Expected error for invalid severity")
		}
	})
}

func TestV1ParserGlobMatching(t *testing.T) {
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
