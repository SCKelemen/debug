package debug

import (
	"os"
	"strings"
	"testing"
)

// Test flags
const (
	TestFlag1 DebugFlag = 1 << iota
	TestFlag2
	TestFlag3
	TestFlag4
	TestFlag5
)

func TestNewDebugManager(t *testing.T) {
	dm := NewDebugManager()

	if dm.flags != 0 {
		t.Errorf("Expected flags to be 0, got %d", dm.flags)
	}

	if dm.severityFilter != SeverityTrace {
		t.Errorf("Expected severity filter to be SeverityTrace, got %v", dm.severityFilter)
	}

	if len(dm.pathFilters) != 0 {
		t.Errorf("Expected path filters to be empty, got %v", dm.pathFilters)
	}

	if !dm.globEnabled {
		t.Error("Expected glob to be enabled by default")
	}
}

func TestRegisterFlags(t *testing.T) {
	dm := NewDebugManager()

	definitions := []FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	}

	dm.RegisterFlags(definitions)

	if len(dm.flagMap) != 3 {
		t.Errorf("Expected 3 flags in flagMap, got %d", len(dm.flagMap))
	}

	if len(dm.pathMap) != 3 {
		t.Errorf("Expected 3 flags in pathMap, got %d", len(dm.pathMap))
	}

	if len(dm.allFlags) != 3 {
		t.Errorf("Expected 3 flags in allFlags, got %d", len(dm.allFlags))
	}

	// Test flag mapping
	if dm.flagMap["test1"] != TestFlag1 {
		t.Errorf("Expected test1 to map to TestFlag1, got %v", dm.flagMap["test1"])
	}

	if dm.pathMap[TestFlag1] != "test.flag1" {
		t.Errorf("Expected TestFlag1 to map to 'test.flag1', got %s", dm.pathMap[TestFlag1])
	}
}

func TestSetFlags(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	})

	// Test individual flags
	err := dm.SetFlags("test1,test2")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !dm.IsEnabled(TestFlag1) {
		t.Error("Expected TestFlag1 to be enabled")
	}

	if !dm.IsEnabled(TestFlag2) {
		t.Error("Expected TestFlag2 to be enabled")
	}

	if dm.IsEnabled(TestFlag3) {
		t.Error("Expected TestFlag3 to be disabled")
	}

	// Test "all" flag
	err = dm.SetFlags("all")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if dm.flags != ^DebugFlag(0) {
		t.Error("Expected all flags to be enabled")
	}

	// Test unknown flag
	err = dm.SetFlags("unknown")
	if err == nil {
		t.Error("Expected error for unknown flag")
	}
}

func TestSetFlagsWithGlob(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
		{TestFlag4, "test4", "other.flag4"},
		{TestFlag5, "test5", "other.flag5"},
	})

	// Test glob pattern
	err := dm.SetFlags("test.*")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !dm.IsEnabled(TestFlag1) {
		t.Error("Expected TestFlag1 to be enabled")
	}

	if !dm.IsEnabled(TestFlag2) {
		t.Error("Expected TestFlag2 to be enabled")
	}

	if !dm.IsEnabled(TestFlag3) {
		t.Error("Expected TestFlag3 to be enabled")
	}

	if dm.IsEnabled(TestFlag4) {
		t.Error("Expected TestFlag4 to be disabled")
	}

	if dm.IsEnabled(TestFlag5) {
		t.Error("Expected TestFlag5 to be disabled")
	}
}

func TestSetSeverityFilter(t *testing.T) {
	dm := NewDebugManager()

	dm.SetSeverityFilter(SeverityInfo)
	if dm.severityFilter != SeverityInfo {
		t.Errorf("Expected severity filter to be SeverityInfo, got %v", dm.severityFilter)
	}
}

func TestSetSeverityFilterFromString(t *testing.T) {
	dm := NewDebugManager()

	testCases := []struct {
		input    string
		expected Severity
		hasError bool
	}{
		{"trace", SeverityTrace, false},
		{"debug", SeverityDebug, false},
		{"info", SeverityInfo, false},
		{"warning", SeverityWarning, false},
		{"warn", SeverityWarning, false},
		{"error", SeverityError, false},
		{"fatal", SeverityFatal, false},
		{"TRACE", SeverityTrace, false},
		{"DEBUG", SeverityDebug, false},
		{"INFO", SeverityInfo, false},
		{"WARNING", SeverityWarning, false},
		{"WARN", SeverityWarning, false},
		{"ERROR", SeverityError, false},
		{"FATAL", SeverityFatal, false},
		{"invalid", SeverityTrace, true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			err := dm.SetSeverityFilterFromString(tc.input)
			if tc.hasError {
				if err == nil {
					t.Errorf("Expected error for input %s", tc.input)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for input %s: %v", tc.input, err)
				}
				if dm.severityFilter != tc.expected {
					t.Errorf("Expected severity %v for input %s, got %v", tc.expected, tc.input, dm.severityFilter)
				}
			}
		})
	}
}

func TestIsEnabled(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
	})

	dm.SetFlags("test1")

	if !dm.IsEnabled(TestFlag1) {
		t.Error("Expected TestFlag1 to be enabled")
	}

	if dm.IsEnabled(TestFlag2) {
		t.Error("Expected TestFlag2 to be disabled")
	}
}

func TestLog(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
	})

	dm.SetFlags("test1")

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.Log(TestFlag1, "Test message")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "DEBUG [test.flag1]: Test message") {
		t.Errorf("Expected log output to contain 'DEBUG [test.flag1]: Test message', got: %s", output)
	}
}

func TestLogWithSeverity(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
	})

	dm.SetFlags("test1")
	dm.SetSeverityFilter(SeverityInfo)

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.LogWithSeverity(TestFlag1, SeverityDebug, "", "Debug message") // Should not be logged
	dm.LogWithSeverity(TestFlag1, SeverityInfo, "", "Info message")   // Should be logged

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if strings.Contains(output, "Debug message") {
		t.Error("Debug message should not be logged due to severity filter")
	}

	if !strings.Contains(output, "Info message") {
		t.Error("Info message should be logged")
	}
}

func TestLogWithContext(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
	})

	dm.SetFlags("test1")

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.LogWithContext(TestFlag1, "test-context", "Test message")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "DEBUG [test.flag1] test-context: Test message") {
		t.Errorf("Expected log output to contain context, got: %s", output)
	}
}

func TestLogWithPath(t *testing.T) {
	dm := NewDebugManager()
	dm.SetPathFilters([]string{"custom.*"})

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.LogWithPath("custom.module", SeverityInfo, "context", "Test message")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "INFO [custom.module] context: Test message") {
		t.Errorf("Expected log output to contain custom path, got: %s", output)
	}
}

func TestMatchesGlob(t *testing.T) {
	dm := NewDebugManager()

	testCases := []struct {
		path     string
		pattern  string
		expected bool
	}{
		{"test.flag1", "test.*", true},
		{"test.flag1", "test.flag1", true},
		{"test.flag1", "test.flag2", false},
		{"test.flag1", "*", true},
		{"test.flag1", "**", true},
		{"test.flag1", "test.flag?", true},
		{"test.flag1", "test.flag*", true},
		{"test.flag1", "other.*", false},
		{"test.api.flag1", "test.**", true},
		{"test.api.flag1", "test.*", true}, // * matches any characters except path separators, but dots are not path separators in our context
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			result := dm.matchesGlob(tc.path, tc.pattern)
			if result != tc.expected {
				t.Errorf("Expected matchesGlob(%s, %s) to be %v, got %v", tc.path, tc.pattern, tc.expected, result)
			}
		})
	}
}

func TestGetEnabledFlags(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	})

	dm.SetFlags("test1,test3")

	enabled := dm.GetEnabledFlags()

	if len(enabled) != 2 {
		t.Errorf("Expected 2 enabled flags, got %d", len(enabled))
	}

	// Check that the correct flags are enabled
	enabledMap := make(map[string]bool)
	for _, flag := range enabled {
		enabledMap[flag] = true
	}

	if !enabledMap["test1"] {
		t.Error("Expected test1 to be in enabled flags")
	}

	if !enabledMap["test3"] {
		t.Error("Expected test3 to be in enabled flags")
	}

	if enabledMap["test2"] {
		t.Error("Expected test2 to not be in enabled flags")
	}
}

func TestGetAvailableFlags(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	})

	available := dm.GetAvailableFlags()

	if len(available) != 3 {
		t.Errorf("Expected 3 available flags, got %d", len(available))
	}

	// Check that all flags are available
	availableMap := make(map[string]bool)
	for _, flag := range available {
		availableMap[flag] = true
	}

	if !availableMap["test1"] {
		t.Error("Expected test1 to be in available flags")
	}

	if !availableMap["test2"] {
		t.Error("Expected test2 to be in available flags")
	}

	if !availableMap["test3"] {
		t.Error("Expected test3 to be in available flags")
	}
}

func TestGetFlagPath(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
	})

	path := dm.GetFlagPath(TestFlag1)
	if path != "test.flag1" {
		t.Errorf("Expected path 'test.flag1', got '%s'", path)
	}

	path = dm.GetFlagPath(TestFlag3) // Unregistered flag
	if path != "unknown" {
		t.Errorf("Expected path 'unknown' for unregistered flag, got '%s'", path)
	}
}

func TestGetFlagName(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
	})

	name := dm.GetFlagName(TestFlag1)
	if name != "test1" {
		t.Errorf("Expected name 'test1', got '%s'", name)
	}

	name = dm.GetFlagName(TestFlag3) // Unregistered flag
	if name != "unknown" {
		t.Errorf("Expected name 'unknown' for unregistered flag, got '%s'", name)
	}
}

func TestEnableGlob(t *testing.T) {
	dm := NewDebugManager()

	dm.EnableGlob(false)
	if dm.globEnabled {
		t.Error("Expected glob to be disabled")
	}

	dm.EnableGlob(true)
	if !dm.globEnabled {
		t.Error("Expected glob to be enabled")
	}
}

func TestSetPathFilters(t *testing.T) {
	dm := NewDebugManager()

	filters := []string{"test.*", "other.*"}
	dm.SetPathFilters(filters)

	if len(dm.pathFilters) != 2 {
		t.Errorf("Expected 2 path filters, got %d", len(dm.pathFilters))
	}

	if dm.pathFilters[0] != "test.*" {
		t.Errorf("Expected first filter to be 'test.*', got '%s'", dm.pathFilters[0])
	}

	if dm.pathFilters[1] != "other.*" {
		t.Errorf("Expected second filter to be 'other.*', got '%s'", dm.pathFilters[1])
	}
}
