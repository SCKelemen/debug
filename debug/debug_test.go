package debug

import (
	"context"
	"testing"
)

func TestUnifiedArchitecture(t *testing.T) {
	// Define test flags
	flagDefs := []FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
	}

	// Test V1 Parser
	t.Run("V1Parser", func(t *testing.T) {
		v1Parser := NewV1Parser()
		dm := NewDebugManager(v1Parser)
		dm.RegisterFlags(flagDefs)

		// Test simple flag enabling
		err := dm.SetFlags("http.request,db.query")
		if err != nil {
			t.Fatalf("SetFlags failed: %v", err)
		}

		if !dm.IsEnabled(1 << 0) {
			t.Error("http.request should be enabled")
		}
		if !dm.IsEnabled(1 << 2) {
			t.Error("db.query should be enabled")
		}
		if dm.IsEnabled(1 << 1) {
			t.Error("http.response should not be enabled")
		}
	})

	// Test V2 Parser
	t.Run("V2Parser", func(t *testing.T) {
		v2Parser := NewV2Parser()
		dm := NewDebugManager(v2Parser)
		dm.RegisterFlags(flagDefs)

		// Test logical expressions
		err := dm.SetFlags("http.request|db.query")
		if err != nil {
			t.Fatalf("SetFlags failed: %v", err)
		}

		if !dm.IsEnabled(1 << 0) {
			t.Error("http.request should be enabled")
		}
		if !dm.IsEnabled(1 << 2) {
			t.Error("db.query should be enabled")
		}
		if dm.IsEnabled(1 << 1) {
			t.Error("http.response should not be enabled")
		}
	})

	// Test V2 Parser with V1 compatibility
	t.Run("V2ParserV1Compatibility", func(t *testing.T) {
		v2Parser := NewV2Parser()
		dm := NewDebugManager(v2Parser)
		dm.RegisterFlags(flagDefs)

		// Test V1 syntax in V2 parser
		err := dm.SetFlags("http.request,db.query")
		if err != nil {
			t.Fatalf("SetFlags failed: %v", err)
		}

		if !dm.IsEnabled(1 << 0) {
			t.Error("http.request should be enabled")
		}
		if !dm.IsEnabled(1 << 2) {
			t.Error("db.query should be enabled")
		}
	})

	// Test context system
	t.Run("ContextSystem", func(t *testing.T) {
		v1Parser := NewV1Parser()
		dm := NewDebugManager(v1Parser)
		dm.RegisterFlags(flagDefs)
		dm.SetFlags("http.request")

		// Test context with debug flags
		ctx := WithDebugFlags(context.Background(), 1<<3) // api.v1.auth.login
		
		// The flag should be enabled because of context
		contextFlags := GetDebugFlagsFromContext(ctx)
		if contextFlags != 1<<3 {
			t.Error("Context should contain api.v1.auth.login flag")
		}
	})

	// Test severity filtering
	t.Run("SeverityFiltering", func(t *testing.T) {
		v1Parser := NewV1Parser()
		dm := NewDebugManager(v1Parser)
		dm.RegisterFlags(flagDefs)

		// Enable flags with severity filtering
		err := dm.SetFlags("http.request:ERROR")
		if err != nil {
			t.Fatalf("SetFlags failed: %v", err)
		}

		// Should have path severity filters
		if len(dm.pathSeverityFilters) == 0 {
			t.Error("Should have path severity filters")
		}
	})
}

func TestParserInterface(t *testing.T) {
	// Test that both parsers implement the FlagParser interface
	var _ FlagParser = (*V1Parser)(nil)
	var _ FlagParser = (*V2Parser)(nil)
}
