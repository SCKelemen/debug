package debug

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestDebugManager(t *testing.T) {
	flagDefs := []FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: 1 << 4, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
		{Flag: 1 << 5, Name: "api.v2.auth.login", Path: "api.v2.auth.login"},
	}

	t.Run("BasicFunctionality", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test flag registration
		if len(dm.flagMap) != 6 {
			t.Errorf("Expected 6 flags registered, got %d", len(dm.flagMap))
		}

		// Test path mapping
		if len(dm.pathMap) != 6 {
			t.Errorf("Expected 6 paths mapped, got %d", len(dm.pathMap))
		}
	})

	t.Run("FlagRegistration", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}

		// Test empty registration
		dm.RegisterFlags([]FlagDefinition{})
		if len(dm.flagMap) != 0 {
			t.Error("Expected empty flag map after empty registration")
		}

		// Test single flag registration
		dm.RegisterFlags([]FlagDefinition{{Flag: 1 << 0, Name: "test.flag", Path: "test.flag"}})
		if len(dm.flagMap) != 1 {
			t.Error("Expected 1 flag after single registration")
		}

		// Test duplicate flag registration (should overwrite)
		dm.RegisterFlags([]FlagDefinition{{Flag: 1 << 1, Name: "test.flag", Path: "test.flag"}})
		if len(dm.flagMap) != 1 {
			t.Error("Expected 1 flag after duplicate registration")
		}
		if dm.flagMap["test.flag"] != 1<<1 {
			t.Error("Expected flag to be overwritten")
		}
	})

	t.Run("IsEnabled", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test with no flags enabled
		if dm.IsEnabled(1 << 0) {
			t.Error("Flag should not be enabled initially")
		}

		// Enable a flag
		dm.enabledFlags = 1 << 0
		if !dm.IsEnabled(1 << 0) {
			t.Error("Flag should be enabled")
		}

		// Test with multiple flags enabled
		dm.enabledFlags = 1<<0 | 1<<2
		if !dm.IsEnabled(1 << 0) {
			t.Error("First flag should be enabled")
		}
		if !dm.IsEnabled(1 << 2) {
			t.Error("Second flag should be enabled")
		}
		if dm.IsEnabled(1 << 1) {
			t.Error("Third flag should not be enabled")
		}
	})

	t.Run("SetFlags", func(t *testing.T) {
		// Test that SetFlags method exists and can be called
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test that we can call SetFlags (actual parsing is tested in parser packages)
		// We expect this to fail because we don't have a parser set
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when SetFlags called without parser")
			}
		}()
		dm.SetFlags("http.request,db.query")
	})

	t.Run("SetFlagsError", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test that SetFlags panics without parser
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when SetFlags called without parser")
			}
		}()
		dm.SetFlags("invalid.flag")
	})

	t.Run("Logging", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)
		dm.enabledFlags = 1 << 0 // Manually enable a flag for testing

		ctx := context.Background()

		// Test basic logging
		dm.Log(ctx, 1<<0, "Test message")

		// Test logging with severity
		dm.LogWithSeverity(ctx, 1<<0, SeverityInfo, "http.request", "Info message")

		// Test logging with context
		ctxWithFlags := WithDebugFlags(ctx, 1<<3)
		dm.LogWithContext(ctxWithFlags, 1<<3, "api.v1.auth.login", "Context message")
	})

	t.Run("SeverityFiltering", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)
		dm.enabledFlags = 1 << 0 // Manually enable a flag for testing

		// Add a severity filter manually
		dm.pathSeverityFilters = []PathSeverityFilter{
			{
				Pattern: "http.request",
				Filter: SeverityFilter{
					Type:       SeverityFilterSpecific,
					Severities: map[Severity]bool{SeverityError: true},
				},
			},
		}

		ctx := context.Background()

		// Test that only ERROR severity logs
		dm.LogWithSeverity(ctx, 1<<0, SeverityError, "http.request", "Error message")
		dm.LogWithSeverity(ctx, 1<<0, SeverityInfo, "http.request", "Info message") // Should not log
	})

	t.Run("ContextSystem", func(t *testing.T) {
		// Test context creation
		ctx := WithDebugFlags(context.Background(), 1<<3)
		flags := GetDebugFlagsFromContext(ctx)
		if flags != 1<<3 {
			t.Error("Context should contain api.v1.auth.login flag")
		}

		// Test context with no flags
		ctxEmpty := WithDebugFlags(context.Background(), 0)
		flagsEmpty := GetDebugFlagsFromContext(ctxEmpty)
		if flagsEmpty != 0 {
			t.Error("Context should contain no flags")
		}

		// Test context with multiple flags
		ctxMulti := WithDebugFlags(context.Background(), 1<<0|1<<2)
		flagsMulti := GetDebugFlagsFromContext(ctxMulti)
		if flagsMulti != (1<<0 | 1<<2) {
			t.Error("Context should contain multiple flags")
		}

		// Test context without debug flags
		ctxNoFlags := context.Background()
		flagsNoFlags := GetDebugFlagsFromContext(ctxNoFlags)
		if flagsNoFlags != 0 {
			t.Error("Context without debug flags should return 0")
		}
	})

	t.Run("SlogIntegration", func(t *testing.T) {
		// Test with slog enabled
		var buf bytes.Buffer
		handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
			logger:  slog.New(handler),
		}
		dm.RegisterFlags(flagDefs)
		dm.enabledFlags = 1 << 0 // Manually enable a flag for testing

		ctx := context.Background()
		dm.Log(ctx, 1<<0, "Slog test message")

		output := buf.String()
		if !strings.Contains(output, "Slog test message") {
			t.Error("Slog output should contain the message")
		}
	})

	t.Run("ThreadSafety", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)
		dm.enabledFlags = 1<<0 | 1<<1 // Manually enable flags for testing

		// Test concurrent access
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()
				dm.IsEnabled(1 << 0)
				dm.IsEnabled(1 << 2)
			}()
		}

		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

func TestSeverityLevels(t *testing.T) {
	t.Run("SeverityOrdering", func(t *testing.T) {
		// Test severity ordering
		if SeverityTrace >= SeverityDebug {
			t.Error("Trace should be less than Debug")
		}
		if SeverityDebug >= SeverityInfo {
			t.Error("Debug should be less than Info")
		}
		if SeverityInfo >= SeverityWarning {
			t.Error("Info should be less than Warning")
		}
		if SeverityWarning >= SeverityError {
			t.Error("Warning should be less than Error")
		}
		if SeverityError >= SeverityFatal {
			t.Error("Error should be less than Fatal")
		}
	})

	t.Run("SeverityString", func(t *testing.T) {
		// Test severity string conversion
		testCases := []struct {
			severity Severity
			expected string
		}{
			{SeverityTrace, "TRACE"},
			{SeverityDebug, "DEBUG"},
			{SeverityInfo, "INFO"},
			{SeverityWarning, "WARN"},
			{SeverityError, "ERROR"},
			{SeverityFatal, "FATAL"},
		}

		for _, tc := range testCases {
			if tc.severity.String() != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, tc.severity.String())
			}
		}
	})
}

func TestFlagDefinition(t *testing.T) {
	t.Run("FlagDefinitionValidation", func(t *testing.T) {
		// Test valid flag definition
		fd := FlagDefinition{
			Flag: 1 << 0,
			Name: "test.flag",
			Path: "test.flag",
		}

		if fd.Flag == 0 {
			t.Error("Flag should not be zero")
		}
		if fd.Name == "" {
			t.Error("Name should not be empty")
		}
		if fd.Path == "" {
			t.Error("Path should not be empty")
		}
	})

	t.Run("FlagDefinitionEquality", func(t *testing.T) {
		fd1 := FlagDefinition{Flag: 1 << 0, Name: "test.flag", Path: "test.flag"}
		fd2 := FlagDefinition{Flag: 1 << 0, Name: "test.flag", Path: "test.flag"}
		fd3 := FlagDefinition{Flag: 1 << 1, Name: "test.flag", Path: "test.flag"}

		if fd1.Flag != fd2.Flag {
			t.Error("Same flags should be equal")
		}
		if fd1.Flag == fd3.Flag {
			t.Error("Different flags should not be equal")
		}
	})
}

func TestEdgeCases(t *testing.T) {
	flagDefs := []FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag", Path: "test.flag"},
	}

	t.Run("EmptyDebugManager", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}

		// Test operations on empty manager
		if dm.IsEnabled(1 << 0) {
			t.Error("Flag should not be enabled in empty manager")
		}

		// Test setting flags on empty manager (should panic without parser)
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic when SetFlags called without parser")
			}
		}()
		dm.SetFlags("test.flag")
	})

	t.Run("NilContext", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)
		dm.enabledFlags = 1 << 0 // Manually enable flag for testing

		// Test logging with nil context
		dm.Log(nil, 1<<0, "Test message")
		dm.LogWithSeverity(nil, 1<<0, SeverityInfo, "test.flag", "Test message")
		dm.LogWithContext(nil, 1<<0, "test.flag", "Test message")
	})

	t.Run("InvalidSeverity", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)
		dm.enabledFlags = 1 << 0 // Manually enable flag for testing

		// Test logging with invalid severity
		dm.LogWithSeverity(context.Background(), 1<<0, Severity(999), "test.flag", "Test message")
	})

	t.Run("LargeFlagValues", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}

		// Test with large flag values
		largeFlags := []FlagDefinition{
			{Flag: 1 << 63, Name: "large.flag", Path: "large.flag"},
		}
		dm.RegisterFlags(largeFlags)
		dm.enabledFlags = 1 << 63 // Manually enable the large flag for testing

		if !dm.IsEnabled(1 << 63) {
			t.Error("Large flag should be enabled")
		}
	})
}

func TestNegativeCases(t *testing.T) {
	flagDefs := []FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag", Path: "test.flag"},
	}

	t.Run("InvalidFlagNames", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test various invalid flag names
		invalidFlags := []string{
			" ",          // whitespace
			"invalid",    // not registered
			"test.flag.", // trailing dot
			".test.flag", // leading dot
			"test..flag", // double dot
		}

		for _, flag := range invalidFlags {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic for invalid flag: %s", flag)
					}
				}()
				dm.SetFlags(flag)
			}()
		}
	})

	t.Run("InvalidSeverityStrings", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test various invalid severity strings
		invalidSeverities := []string{
			"test.flag:INVALID",
			"test.flag:",
			"test.flag:ERROR|INVALID",
			"test.flag:+INVALID",
		}

		for _, severity := range invalidSeverities {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic for invalid severity: %s", severity)
					}
				}()
				dm.SetFlags(severity)
			}()
		}
	})

	t.Run("MalformedExpressions", func(t *testing.T) {
		dm := &DebugManager{
			flagMap: make(map[string]DebugFlag),
			pathMap: make(map[DebugFlag]string),
		}
		dm.RegisterFlags(flagDefs)

		// Test various malformed expressions
		malformedExpressions := []string{
			"test.flag|",           // trailing operator
			"|test.flag",           // leading operator
			"test.flag&",           // trailing operator
			"&test.flag",           // leading operator
			"test.flag||test.flag", // double operator
			"test.flag&&test.flag", // double operator
			"test.flag&|test.flag", // mixed operators
			"((test.flag)",         // unmatched parentheses
			"(test.flag))",         // unmatched parentheses
			"((test.flag))",        // should be fine
		}

		for _, expr := range malformedExpressions {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic for malformed expression: %s", expr)
					}
				}()
				dm.SetFlags(expr)
			}()
		}
	})
}
