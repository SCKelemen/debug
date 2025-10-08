package v2

import (
	"bytes"
	"log/slog"
	"os"
	"testing"
)

func TestNewDebugManager(t *testing.T) {
	dm := NewDebugManager()
	if dm == nil {
		t.Fatal("NewDebugManager returned nil")
	}
	if dm.flags != 0 {
		t.Errorf("Expected flags to be 0, got %d", dm.flags)
	}
	if dm.severityFilter != SeverityTrace {
		t.Errorf("Expected severity filter to be SeverityTrace, got %v", dm.severityFilter)
	}
	if dm.useSlog {
		t.Error("Expected useSlog to be false by default")
	}
}

func TestRegisterFlags(t *testing.T) {
	dm := NewDebugManager()
	
	definitions := []FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
	}
	
	dm.RegisterFlags(definitions)
	
	if len(dm.flagMap) != 2 {
		t.Errorf("Expected flagMap to have 2 entries, got %d", len(dm.flagMap))
	}
	if len(dm.pathMap) != 2 {
		t.Errorf("Expected pathMap to have 2 entries, got %d", len(dm.pathMap))
	}
	if len(dm.allFlags) != 2 {
		t.Errorf("Expected allFlags to have 2 entries, got %d", len(dm.allFlags))
	}
	
	if dm.flagMap["test.flag1"] != 1<<0 {
		t.Error("Flag1 not registered correctly")
	}
	if dm.pathMap[1<<0] != "test.flag1" {
		t.Error("Path1 not registered correctly")
	}
}

func TestSetFlagsV1Compatibility(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
	})
	
	// V2 should support V1 comma-separated syntax
	err := dm.SetFlags("test.flag1,test.flag2")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	if !dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should be enabled")
	}
	if !dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should be enabled")
	}
}

func TestSetFlagsV2LogicalExpressions(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
		{Flag: 1 << 2, Name: "test.flag3", Path: "test.flag3"},
	})
	
	// Test OR expression
	err := dm.SetFlags("test.flag1|test.flag2")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	if !dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should be enabled")
	}
	if !dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should be enabled")
	}
	if dm.IsEnabled(1 << 2) {
		t.Error("test.flag3 should not be enabled")
	}
}

func TestSetFlagsV2AndExpression(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
	})
	
	// Test AND expression - should only enable flags that match the AND condition
	// Since no flags are initially enabled, AND should result in no flags enabled
	err := dm.SetFlags("test.flag1&test.flag2")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	// No flags should be enabled (AND of no flags)
	if dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should not be enabled (AND of no flags)")
	}
	if dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should not be enabled (AND of no flags)")
	}
	
	// Test with a single flag - should not be enabled (AND requires both)
	err = dm.SetFlags("test.flag1")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	// Apply AND filter - should disable the single flag
	err = dm.SetFlags("test.flag1&test.flag2")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	// No flags should be enabled (AND requires both flags)
	if dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should not be enabled (AND requires both flags)")
	}
	if dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should not be enabled (AND requires both flags)")
	}
}

func TestSetFlagsV2NotExpression(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
	})
	
	// Enable everything except test.flag1
	err := dm.SetFlags("!test.flag1")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	if dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should not be enabled")
	}
	if !dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should be enabled")
	}
}

func TestSetFlagsV2ComplexExpression(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
		{Flag: 1 << 2, Name: "test.flag3", Path: "test.flag3"},
	})
	
	// Complex expression: (test.flag1|test.flag2)&!test.flag3
	err := dm.SetFlags("(test.flag1|test.flag2)&!test.flag3")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	if !dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should be enabled")
	}
	if !dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should be enabled")
	}
	if dm.IsEnabled(1 << 2) {
		t.Error("test.flag3 should not be enabled")
	}
}

func TestSetFlagsGlob(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
		{Flag: 1 << 2, Name: "other.flag1", Path: "other.flag1"},
	})
	
	err := dm.SetFlags("test.*")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	if !dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should be enabled")
	}
	if !dm.IsEnabled(1 << 1) {
		t.Error("test.flag2 should be enabled")
	}
	if dm.IsEnabled(1 << 2) {
		t.Error("other.flag1 should not be enabled")
	}
}

func TestSetFlagsAll(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
	})
	
	err := dm.SetFlags("all")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	// All bits should be set
	if dm.flags != ^DebugFlag(0) {
		t.Error("All flags should be enabled")
	}
}

func TestSetFlagsWithSeverity(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
	})
	
	err := dm.SetFlags("test.flag1:ERROR")
	if err != nil {
		t.Fatalf("SetFlags failed: %v", err)
	}
	
	if !dm.IsEnabled(1 << 0) {
		t.Error("test.flag1 should be enabled")
	}
	
	if len(dm.pathSeverityFilters) != 1 {
		t.Errorf("Expected 1 path severity filter, got %d", len(dm.pathSeverityFilters))
	}
	
	filter := dm.pathSeverityFilters[0]
	if filter.Pattern != "test.flag1" {
		t.Errorf("Expected pattern 'test.flag1', got '%s'", filter.Pattern)
	}
	if filter.Filter.Type != SeverityFilterSpecific {
		t.Error("Expected SeverityFilterSpecific")
	}
	if !filter.Filter.Severities[SeverityError] {
		t.Error("Expected ERROR severity to be enabled")
	}
}

func TestLogging(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
	})
	
	dm.SetFlags("test.flag1")
	
	// Capture output
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	
	dm.Log(1<<0, "test message")
	
	w.Close()
	os.Stderr = oldStderr
	
	var buf bytes.Buffer
	buf.ReadFrom(r)
	
	if !bytes.Contains(buf.Bytes(), []byte("test message")) {
		t.Error("Expected log message to contain 'test message'")
	}
	if !bytes.Contains(buf.Bytes(), []byte("test.flag1")) {
		t.Error("Expected log message to contain flag path")
	}
}

func TestContextSystem(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "parent.flag", Path: "parent.flag"},
		{Flag: 1 << 1, Name: "child.flag", Path: "child.flag"},
	})
	
	dm.SetFlags("parent.flag,child.flag")
	
	// Test PushContext and PopContext
	dm.PushContext(1 << 0)
	if dm.GetContext() != 1<<0 {
		t.Error("Context should be parent.flag")
	}
	
	dm.PushContext(1 << 1)
	if dm.GetContext() != (1<<0)|(1<<1) {
		t.Error("Context should be parent.flag | child.flag")
	}
	
	popped := dm.PopContext()
	if popped != 1<<1 {
		t.Error("Popped context should be child.flag")
	}
	
	if dm.GetContext() != 1<<0 {
		t.Error("Context should be parent.flag after pop")
	}
	
	// Test WithContext
	dm.ClearContext()
	dm.WithContext(1<<0, func() {
		if dm.GetContext() != 1<<0 {
			t.Error("Context should be parent.flag in WithContext")
		}
	})
	
	if dm.GetContext() != 0 {
		t.Error("Context should be cleared after WithContext")
	}
}

func TestSlogIntegration(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
	})
	
	dm.SetFlags("test.flag1")
	
	// Test enabling slog
	if dm.IsSlogEnabled() {
		t.Error("Slog should not be enabled by default")
	}
	
	dm.EnableSlog()
	if !dm.IsSlogEnabled() {
		t.Error("Slog should be enabled after EnableSlog")
	}
	
	// Test custom handler
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	dm.EnableSlogWithHandler(handler)
	
	dm.Log(1<<0, "slog test message")
	
	if !bytes.Contains(buf.Bytes(), []byte("slog test message")) {
		t.Error("Expected slog message to contain 'slog test message'")
	}
	
	// Test disabling slog
	dm.DisableSlog()
	if dm.IsSlogEnabled() {
		t.Error("Slog should be disabled after DisableSlog")
	}
}

func TestV2LogicalExpressionParsing(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "a", Path: "a"},
		{Flag: 1 << 1, Name: "b", Path: "b"},
		{Flag: 1 << 2, Name: "c", Path: "c"},
	})
	
	testCases := []struct {
		expression string
		expected   DebugFlag
	}{
		{"a|b", (1 << 0) | (1 << 1)},
		{"a&b", 0}, // No flags enabled initially
		{"!a", ^DebugFlag(1 << 0)}, // All flags except a
		{"(a|b)&c", 0}, // No flags enabled initially
		{"a|(b&c)", 1 << 0}, // Only a is enabled
	}
	
	for _, tc := range testCases {
		t.Run(tc.expression, func(t *testing.T) {
			err := dm.SetFlags(tc.expression)
			if err != nil {
				t.Fatalf("SetFlags failed for %s: %v", tc.expression, err)
			}
			
			if dm.flags != tc.expected {
				t.Errorf("Expected flags %d for expression %s, got %d", tc.expected, tc.expression, dm.flags)
			}
		})
	}
}

func TestV2BackwardCompatibility(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{Flag: 1 << 0, Name: "test.flag1", Path: "test.flag1"},
		{Flag: 1 << 1, Name: "test.flag2", Path: "test.flag2"},
	})
	
	// V2 should support all V1 syntax
	v1Expressions := []string{
		"test.flag1",
		"test.flag1,test.flag2",
		"test.*",
		"all",
		"**",
	}
	
	for _, expr := range v1Expressions {
		t.Run(expr, func(t *testing.T) {
			err := dm.SetFlags(expr)
			if err != nil {
				t.Errorf("V2 should support V1 expression %s: %v", expr, err)
			}
		})
	}
}
