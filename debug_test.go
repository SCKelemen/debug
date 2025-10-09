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

	// Test basic functionality without parser imports to avoid cycles
	t.Run("BasicFunctionality", func(t *testing.T) {
		// Test that we can create a debug manager (this will be tested with actual parsers in their own packages)
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test flag registration
		if len(dm.flagMap) != 4 {
			t.Errorf("Expected 4 flags registered, got %d", len(dm.flagMap))
		}
	})

	// Test context system
	t.Run("ContextSystem", func(t *testing.T) {
		// Test context with debug flags
		ctx := WithDebugFlags(context.Background(), 1<<3) // api.v1.auth.login
		
		// The flag should be enabled because of context
		contextFlags := GetDebugFlagsFromContext(ctx)
		if contextFlags != 1<<3 {
			t.Error("Context should contain api.v1.auth.login flag")
		}
	})
}

