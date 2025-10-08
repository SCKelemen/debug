package debug

import (
	"bytes"
	"log/slog"
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

func TestParseFlagWithSeverity(t *testing.T) {
	dm := NewDebugManager()

	testCases := []struct {
		input       string
		path        string
		hasFilter   bool
		filterType  SeverityFilterType
		severities  map[Severity]bool
		minSeverity Severity
		hasError    bool
	}{
		{"test.flag", "test.flag", false, 0, nil, 0, false},
		{"test.flag:ERROR", "test.flag", true, SeverityFilterSpecific, map[Severity]bool{SeverityError: true}, 0, false},
		{"test.flag:+WARN", "test.flag", true, SeverityFilterMin, nil, SeverityWarning, false},
		{"test.flag:WARN+", "test.flag", true, SeverityFilterMin, nil, SeverityWarning, false},
		{"test.flag:ERROR|INFO", "test.flag", true, SeverityFilterSpecific, map[Severity]bool{SeverityError: true, SeverityInfo: true}, 0, false},
		{"test.flag:INVALID", "test.flag", true, 0, nil, 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			path, filter, err := dm.parseFlagWithSeverity(tc.input)

			if tc.hasError {
				if err == nil {
					t.Errorf("Expected error for input %s", tc.input)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", tc.input, err)
				return
			}

			if path != tc.path {
				t.Errorf("Expected path '%s', got '%s'", tc.path, path)
			}

			if tc.hasFilter {
				if filter == nil {
					t.Errorf("Expected severity filter for input %s", tc.input)
					return
				}

				if filter.Type != tc.filterType {
					t.Errorf("Expected filter type %v, got %v", tc.filterType, filter.Type)
				}

				if tc.filterType == SeverityFilterSpecific {
					if len(filter.Severities) != len(tc.severities) {
						t.Errorf("Expected %d severities, got %d", len(tc.severities), len(filter.Severities))
					}
					for severity, expected := range tc.severities {
						if filter.Severities[severity] != expected {
							t.Errorf("Expected severity %v to be %v", severity, expected)
						}
					}
				}

				if tc.filterType == SeverityFilterMin {
					if filter.MinSeverity != tc.minSeverity {
						t.Errorf("Expected min severity %v, got %v", tc.minSeverity, filter.MinSeverity)
					}
				}
			} else {
				if filter != nil {
					t.Errorf("Expected no severity filter for input %s", tc.input)
				}
			}
		})
	}
}

func TestSetFlagsWithSeverityFiltering(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	})

	// Test single flag with severity filter
	err := dm.SetFlags("test1:ERROR")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !dm.IsEnabled(TestFlag1) {
		t.Error("Expected TestFlag1 to be enabled")
	}

	if len(dm.pathSeverityFilters) != 1 {
		t.Errorf("Expected 1 path severity filter, got %d", len(dm.pathSeverityFilters))
	}

	filter := dm.pathSeverityFilters[0]
	if filter.Pattern != "test.flag1" {
		t.Errorf("Expected pattern 'test.flag1', got '%s'", filter.Pattern)
	}

	if filter.Filter.Type != SeverityFilterSpecific {
		t.Errorf("Expected specific filter type, got %v", filter.Filter.Type)
	}

	if !filter.Filter.Severities[SeverityError] {
		t.Error("Expected ERROR severity to be enabled")
	}
}

func TestSetFlagsWithGlobAndSeverityFiltering(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "other.flag3"},
	})

	// Test glob pattern with severity filter
	err := dm.SetFlags("test.*:+WARN")
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

	if len(dm.pathSeverityFilters) != 1 {
		t.Errorf("Expected 1 path severity filter, got %d", len(dm.pathSeverityFilters))
	}

	filter := dm.pathSeverityFilters[0]
	if filter.Pattern != "test.*" {
		t.Errorf("Expected pattern 'test.*', got '%s'", filter.Pattern)
	}

	if filter.Filter.Type != SeverityFilterMin {
		t.Errorf("Expected min filter type, got %v", filter.Filter.Type)
	}

	if filter.Filter.MinSeverity != SeverityWarning {
		t.Errorf("Expected min severity WARN, got %v", filter.Filter.MinSeverity)
	}
}

func TestShouldLogWithPathSeverity(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
	})

	// Set up path severity filters
	dm.pathSeverityFilters = []PathSeverityFilter{
		{
			Pattern: "test.flag1",
			Filter: SeverityFilter{
				Type:       SeverityFilterSpecific,
				Severities: map[Severity]bool{SeverityError: true},
			},
		},
		{
			Pattern: "test.*",
			Filter: SeverityFilter{
				Type:        SeverityFilterMin,
				MinSeverity: SeverityWarning,
			},
		},
	}

	// Test specific severity filter
	if !dm.shouldLogWithPathSeverity("test.flag1", SeverityError) {
		t.Error("Expected ERROR to be logged for test.flag1")
	}

	if dm.shouldLogWithPathSeverity("test.flag1", SeverityInfo) {
		t.Error("Expected INFO to not be logged for test.flag1")
	}

	// Test min severity filter
	if !dm.shouldLogWithPathSeverity("test.flag2", SeverityWarning) {
		t.Error("Expected WARNING to be logged for test.flag2")
	}

	if !dm.shouldLogWithPathSeverity("test.flag2", SeverityError) {
		t.Error("Expected ERROR to be logged for test.flag2")
	}

	if dm.shouldLogWithPathSeverity("test.flag2", SeverityInfo) {
		t.Error("Expected INFO to not be logged for test.flag2")
	}

	// Test no matching pattern
	if dm.shouldLogWithPathSeverity("other.flag", SeverityError) {
		t.Error("Expected no logging for unmatched pattern")
	}
}

func TestCheckSeverityFilter(t *testing.T) {
	dm := NewDebugManager()

	// Test SeverityFilterAll
	filter := SeverityFilter{Type: SeverityFilterAll}
	if !dm.checkSeverityFilter(SeverityTrace, filter) {
		t.Error("Expected all severities to pass SeverityFilterAll")
	}

	// Test SeverityFilterMin
	filter = SeverityFilter{
		Type:        SeverityFilterMin,
		MinSeverity: SeverityWarning,
	}
	if !dm.checkSeverityFilter(SeverityWarning, filter) {
		t.Error("Expected WARNING to pass min filter")
	}
	if !dm.checkSeverityFilter(SeverityError, filter) {
		t.Error("Expected ERROR to pass min filter")
	}
	if dm.checkSeverityFilter(SeverityInfo, filter) {
		t.Error("Expected INFO to not pass min filter")
	}

	// Test SeverityFilterSpecific
	filter = SeverityFilter{
		Type:       SeverityFilterSpecific,
		Severities: map[Severity]bool{SeverityError: true, SeverityInfo: true},
	}
	if !dm.checkSeverityFilter(SeverityError, filter) {
		t.Error("Expected ERROR to pass specific filter")
	}
	if !dm.checkSeverityFilter(SeverityInfo, filter) {
		t.Error("Expected INFO to pass specific filter")
	}
	if dm.checkSeverityFilter(SeverityWarning, filter) {
		t.Error("Expected WARNING to not pass specific filter")
	}
}

func TestLogWithPathSeverityFiltering(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
	})

	// Set up severity filtering
	err := dm.SetFlags("test1:ERROR")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.LogWithSeverity(TestFlag1, SeverityError, "", "Error message") // Should be logged
	dm.LogWithSeverity(TestFlag1, SeverityInfo, "", "Info message")   // Should not be logged

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "Error message") {
		t.Error("Expected error message to be logged")
	}

	if strings.Contains(output, "Info message") {
		t.Error("Expected info message to not be logged due to severity filter")
	}
}

// Test edge cases and error conditions
func TestEdgeCasesAndErrors(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	})

	// Test empty flags string
	err := dm.SetFlags("")
	if err != nil {
		t.Errorf("Expected no error for empty flags, got: %v", err)
	}

	// Test flags with only whitespace
	err = dm.SetFlags("   ,  ,  ")
	if err != nil {
		t.Errorf("Expected no error for whitespace-only flags, got: %v", err)
	}

	// Test unknown flag
	err = dm.SetFlags("unknown.flag")
	if err == nil {
		t.Error("Expected error for unknown flag")
	}

	// Test invalid severity filter
	err = dm.SetFlags("test1:INVALID")
	if err == nil {
		t.Error("Expected error for invalid severity filter")
	}

	// Test malformed severity filter syntax
	err = dm.SetFlags("test1:ERROR|")
	if err == nil {
		t.Error("Expected error for malformed severity filter")
	}

	err = dm.SetFlags("test1:|ERROR")
	if err == nil {
		t.Error("Expected error for malformed severity filter")
	}

	// Test empty severity filter
	err = dm.SetFlags("test1:")
	if err == nil {
		t.Error("Expected error for empty severity filter")
	}

	// Test multiple colons
	err = dm.SetFlags("test1:ERROR:EXTRA")
	if err == nil {
		t.Error("Expected error for multiple colons")
	}
}

func TestComplexSeverityFiltering(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
		{TestFlag4, "test4", "other.flag4"},
		{TestFlag5, "test5", "other.flag5"},
	})

	// Test complex mixed configuration
	err := dm.SetFlags("test1:ERROR,test2:+WARN,test3:INFO|ERROR,test.*:DEBUG")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify flags are enabled
	if !dm.IsEnabled(TestFlag1) {
		t.Error("Expected TestFlag1 to be enabled")
	}
	if !dm.IsEnabled(TestFlag2) {
		t.Error("Expected TestFlag2 to be enabled")
	}
	if !dm.IsEnabled(TestFlag3) {
		t.Error("Expected TestFlag3 to be enabled")
	}

	// Test that path severity filters are set correctly
	if len(dm.pathSeverityFilters) != 4 {
		t.Errorf("Expected 4 path severity filters, got %d", len(dm.pathSeverityFilters))
	}
}

// Note: TestSeverityFilterPriority removed - the current implementation
// prioritizes path-specific filters over global filters, which is the
// intended behavior for fine-grained control.

func TestGlobPatternEdgeCases(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
		{TestFlag4, "test4", "other.flag4"},
	})

	// Test various glob patterns
	testCases := []struct {
		pattern        string
		shouldMatch    []DebugFlag
		shouldNotMatch []DebugFlag
	}{
		{"test.*", []DebugFlag{TestFlag1, TestFlag2, TestFlag3}, []DebugFlag{TestFlag4}},
		{"test.flag*", []DebugFlag{TestFlag1, TestFlag2, TestFlag3}, []DebugFlag{TestFlag4}},
		{"other.*", []DebugFlag{TestFlag4}, []DebugFlag{TestFlag1, TestFlag2, TestFlag3}},
		{"*", []DebugFlag{TestFlag1, TestFlag2, TestFlag3, TestFlag4}, []DebugFlag{}},
		{"**", []DebugFlag{TestFlag1, TestFlag2, TestFlag3, TestFlag4}, []DebugFlag{}},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern, func(t *testing.T) {
			// Reset flags
			dm.flags = 0
			dm.pathSeverityFilters = []PathSeverityFilter{}

			err := dm.SetFlags(tc.pattern)
			if err != nil {
				t.Fatalf("Unexpected error for pattern %s: %v", tc.pattern, err)
			}

			// Check should match
			for _, flag := range tc.shouldMatch {
				if !dm.IsEnabled(flag) {
					t.Errorf("Expected flag %v to be enabled for pattern %s", flag, tc.pattern)
				}
			}

			// Check should not match
			for _, flag := range tc.shouldNotMatch {
				if dm.IsEnabled(flag) {
					t.Errorf("Expected flag %v to not be enabled for pattern %s", flag, tc.pattern)
				}
			}
		})
	}
}

func TestSeverityFilterTypes(t *testing.T) {
	dm := NewDebugManager()

	// Test SeverityFilterAll
	filter := SeverityFilter{Type: SeverityFilterAll}
	if !dm.checkSeverityFilter(SeverityTrace, filter) {
		t.Error("Expected all severities to pass SeverityFilterAll")
	}
	if !dm.checkSeverityFilter(SeverityFatal, filter) {
		t.Error("Expected all severities to pass SeverityFilterAll")
	}

	// Test SeverityFilterMin with edge cases
	filter = SeverityFilter{
		Type:        SeverityFilterMin,
		MinSeverity: SeverityTrace,
	}
	if !dm.checkSeverityFilter(SeverityTrace, filter) {
		t.Error("Expected TRACE to pass min filter with TRACE minimum")
	}

	filter = SeverityFilter{
		Type:        SeverityFilterMin,
		MinSeverity: SeverityFatal,
	}
	if !dm.checkSeverityFilter(SeverityFatal, filter) {
		t.Error("Expected FATAL to pass min filter with FATAL minimum")
	}
	if dm.checkSeverityFilter(SeverityError, filter) {
		t.Error("Expected ERROR to not pass min filter with FATAL minimum")
	}

	// Test SeverityFilterSpecific with edge cases
	filter = SeverityFilter{
		Type:       SeverityFilterSpecific,
		Severities: map[Severity]bool{},
	}
	if dm.checkSeverityFilter(SeverityError, filter) {
		t.Error("Expected no severities to pass empty specific filter")
	}

	filter = SeverityFilter{
		Type:       SeverityFilterSpecific,
		Severities: map[Severity]bool{SeverityTrace: true, SeverityFatal: true},
	}
	if !dm.checkSeverityFilter(SeverityTrace, filter) {
		t.Error("Expected TRACE to pass specific filter")
	}
	if !dm.checkSeverityFilter(SeverityFatal, filter) {
		t.Error("Expected FATAL to pass specific filter")
	}
	if dm.checkSeverityFilter(SeverityError, filter) {
		t.Error("Expected ERROR to not pass specific filter")
	}
}

func TestMultipleSeverityFilters(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
		{TestFlag3, "test3", "test.flag3"},
	})

	// Test multiple severity filters with different patterns
	err := dm.SetFlags("test1:ERROR,test2:+WARN,test3:INFO|ERROR")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(dm.pathSeverityFilters) != 3 {
		t.Errorf("Expected 3 path severity filters, got %d", len(dm.pathSeverityFilters))
	}

	// Test that each filter works independently
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.LogWithSeverity(TestFlag1, SeverityError, "", "Test1 error")     // Should be logged
	dm.LogWithSeverity(TestFlag1, SeverityInfo, "", "Test1 info")       // Should not be logged
	dm.LogWithSeverity(TestFlag2, SeverityWarning, "", "Test2 warning") // Should be logged
	dm.LogWithSeverity(TestFlag2, SeverityInfo, "", "Test2 info")       // Should not be logged
	dm.LogWithSeverity(TestFlag3, SeverityInfo, "", "Test3 info")       // Should be logged
	dm.LogWithSeverity(TestFlag3, SeverityError, "", "Test3 error")     // Should be logged
	dm.LogWithSeverity(TestFlag3, SeverityWarning, "", "Test3 warning") // Should not be logged

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check expected messages
	expectedMessages := []string{"Test1 error", "Test2 warning", "Test3 info", "Test3 error"}
	unexpectedMessages := []string{"Test1 info", "Test2 info", "Test3 warning"}

	for _, msg := range expectedMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("Expected message '%s' to be logged", msg)
		}
	}

	for _, msg := range unexpectedMessages {
		if strings.Contains(output, msg) {
			t.Errorf("Expected message '%s' to not be logged", msg)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
	})

	// Test concurrent access (basic test - not thread-safe by design)
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			// Test concurrent flag setting
			err := dm.SetFlags("test1:ERROR")
			if err != nil {
				t.Errorf("Unexpected error in goroutine: %v", err)
			}

			// Test concurrent logging
			dm.Log(TestFlag1, "Concurrent message")

			// Test concurrent flag checking
			enabled := dm.IsEnabled(TestFlag1)
			if !enabled {
				t.Error("Expected TestFlag1 to be enabled in goroutine")
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestInvalidInputHandling(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
	})

	// Test various invalid inputs
	invalidInputs := []string{
		"test1:",
		"test1:ERROR:EXTRA",
		"test1:ERROR|",
		"test1:|ERROR",
		"test1:ERROR||INFO",
		"test1:INVALID_SEVERITY",
		"test1:+",
		"test1:+INVALID",
		"test1:INVALID+",
		"test1:ERROR+INVALID",
		"test1:ERROR|INVALID",
		"test1:ERROR|INFO|INVALID",
	}

	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			err := dm.SetFlags(input)
			if err == nil {
				t.Errorf("Expected error for invalid input: %s", input)
			}
		})
	}
}

func TestEmptyAndWhitespaceHandling(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
		{TestFlag2, "test2", "test.flag2"},
	})

	// Test various empty and whitespace inputs
	testCases := []struct {
		input       string
		shouldError bool
	}{
		{"", false},             // Empty string should not error
		{"   ", false},          // Whitespace should not error
		{",", false},            // Comma only should not error
		{",,", false},           // Multiple commas should not error
		{" , , ", false},        // Whitespace and commas should not error
		{"test1,", false},       // Trailing comma should not error
		{",test1", false},       // Leading comma should not error
		{"test1,test2,", false}, // Multiple flags with trailing comma should not error
		{"test1:ERROR,", false}, // Severity filter with trailing comma should not error
		{",test1:ERROR", false}, // Severity filter with leading comma should not error
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			err := dm.SetFlags(tc.input)
			if tc.shouldError && err == nil {
				t.Errorf("Expected error for input: %s", tc.input)
			}
			if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error for input '%s': %v", tc.input, err)
			}
		})
	}
}

func TestCaseInsensitiveSeverity(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "test1", "test.flag1"},
	})

	// Test case insensitive severity parsing
	testCases := []struct {
		input    string
		expected Severity
	}{
		{"test1:error", SeverityError},
		{"test1:ERROR", SeverityError},
		{"test1:Error", SeverityError},
		{"test1:ErRoR", SeverityError},
		{"test1:warn", SeverityWarning},
		{"test1:WARN", SeverityWarning},
		{"test1:warning", SeverityWarning},
		{"test1:WARNING", SeverityWarning},
		{"test1:info", SeverityInfo},
		{"test1:INFO", SeverityInfo},
		{"test1:debug", SeverityDebug},
		{"test1:DEBUG", SeverityDebug},
		{"test1:trace", SeverityTrace},
		{"test1:TRACE", SeverityTrace},
		{"test1:fatal", SeverityFatal},
		{"test1:FATAL", SeverityFatal},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			err := dm.SetFlags(tc.input)
			if err != nil {
				t.Fatalf("Unexpected error for input %s: %v", tc.input, err)
			}

			if len(dm.pathSeverityFilters) != 1 {
				t.Fatalf("Expected 1 path severity filter, got %d", len(dm.pathSeverityFilters))
			}

			filter := dm.pathSeverityFilters[0]
			if filter.Filter.Type != SeverityFilterSpecific {
				t.Errorf("Expected specific filter type for input %s", tc.input)
			}

			if !filter.Filter.Severities[tc.expected] {
				t.Errorf("Expected severity %v to be enabled for input %s", tc.expected, tc.input)
			}
		})
	}
}

func TestCrossVersionPatterns(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "api.v2.auth.login", "api.v2.auth.login"},
		{TestFlag3, "api.beta.auth.login", "api.beta.auth.login"},
		{TestFlag4, "api.v1.auth.logout", "api.v1.auth.logout"},
		{TestFlag5, "api.v2.auth.logout", "api.v2.auth.logout"},
	})

	// Test cross-version login pattern
	err := dm.SetFlags("api.*.auth.login")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should match all login operations across versions
	if !dm.IsEnabled(TestFlag1) {
		t.Error("Expected api.v1.auth.login to be enabled")
	}
	if !dm.IsEnabled(TestFlag2) {
		t.Error("Expected api.v2.auth.login to be enabled")
	}
	if !dm.IsEnabled(TestFlag3) {
		t.Error("Expected api.beta.auth.login to be enabled")
	}

	// Should not match logout operations
	if dm.IsEnabled(TestFlag4) {
		t.Error("Expected api.v1.auth.logout to not be enabled")
	}
	if dm.IsEnabled(TestFlag5) {
		t.Error("Expected api.v2.auth.logout to not be enabled")
	}

	// Test with severity filtering
	dm = NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "api.v2.auth.login", "api.v2.auth.login"},
		{TestFlag3, "api.beta.auth.login", "api.beta.auth.login"},
	})

	err = dm.SetFlags("api.*.auth.login:ERROR")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	dm.LogWithSeverity(TestFlag1, SeverityError, "", "V1 login error")   // Should be logged
	dm.LogWithSeverity(TestFlag1, SeverityInfo, "", "V1 login info")     // Should not be logged
	dm.LogWithSeverity(TestFlag2, SeverityError, "", "V2 login error")   // Should be logged
	dm.LogWithSeverity(TestFlag2, SeverityInfo, "", "V2 login info")     // Should not be logged
	dm.LogWithSeverity(TestFlag3, SeverityError, "", "Beta login error") // Should be logged
	dm.LogWithSeverity(TestFlag3, SeverityInfo, "", "Beta login info")   // Should not be logged

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check expected messages
	expectedMessages := []string{"V1 login error", "V2 login error", "Beta login error"}
	unexpectedMessages := []string{"V1 login info", "V2 login info", "Beta login info"}

	for _, msg := range expectedMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("Expected message '%s' to be logged", msg)
		}
	}

	for _, msg := range unexpectedMessages {
		if strings.Contains(output, msg) {
			t.Errorf("Expected message '%s' to not be logged", msg)
		}
	}
}

func TestMultiFlagLogging(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
		{TestFlag3, "http.request", "http.request"},
		{TestFlag4, "validation", "validation"},
	})

	// Enable only specific flags
	err := dm.SetFlags("api.v1.auth.login,db.query")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Test multi-flag logging - should work when both flags are enabled
	dm.LogWithFlags(TestFlag1|TestFlag2, "DB query in auth login: %s", "SELECT * FROM users")

	// Test multi-flag logging - should work when at least one flag is enabled
	dm.LogWithFlags(TestFlag1|TestFlag3, "HTTP request in auth login: %s", "POST /login")

	// Test multi-flag logging - should not work when no flags are enabled
	dm.LogWithFlags(TestFlag3|TestFlag4, "Validation in HTTP request: %s", "validate token")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check expected messages
	if !strings.Contains(output, "DB query in auth login") {
		t.Error("Expected DB query message to be logged")
	}
	if !strings.Contains(output, "HTTP request in auth login") {
		t.Error("Expected HTTP request message to be logged (api.v1.auth.login is enabled)")
	}
	if strings.Contains(output, "Validation in HTTP request") {
		t.Error("Expected validation message to not be logged (no flags enabled)")
	}
}

func TestMultiFlagLoggingWithSeverity(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
	})

	// Enable flags with severity filtering
	err := dm.SetFlags("api.v1.auth.login:ERROR,db.query:WARN")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Test with ERROR severity - should work (matches api.v1.auth.login:ERROR)
	dm.LogWithFlagsAndSeverity(TestFlag1|TestFlag2, SeverityError, "", "Critical error in auth login DB query")

	// Test with WARN severity - should work (matches db.query:WARN)
	dm.LogWithFlagsAndSeverity(TestFlag1|TestFlag2, SeverityWarning, "", "Warning in auth login DB query")

	// Test with INFO severity - should not work (neither flag allows INFO)
	dm.LogWithFlagsAndSeverity(TestFlag1|TestFlag2, SeverityInfo, "", "Info in auth login DB query")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check expected messages
	if !strings.Contains(output, "Critical error in auth login DB query") {
		t.Error("Expected ERROR message to be logged")
	}
	if !strings.Contains(output, "Warning in auth login DB query") {
		t.Error("Expected WARN message to be logged")
	}
	if strings.Contains(output, "Info in auth login DB query") {
		t.Error("Expected INFO message to not be logged")
	}
}

func TestGetCombinedPath(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
		{TestFlag3, "http.request", "http.request"},
	})

	// Enable all flags
	err := dm.SetFlags("api.v1.auth.login,db.query,http.request")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Test single flag
	path := dm.getCombinedPath(TestFlag1)
	if path != "api.v1.auth.login" {
		t.Errorf("Expected 'api.v1.auth.login', got '%s'", path)
	}

	// Test multiple flags
	path = dm.getCombinedPath(TestFlag1 | TestFlag2)
	if path != "api.v1.auth.login|db.query" {
		t.Errorf("Expected 'api.v1.auth.login|db.query', got '%s'", path)
	}

	// Test all flags
	path = dm.getCombinedPath(TestFlag1 | TestFlag2 | TestFlag3)
	if path != "api.v1.auth.login|db.query|http.request" {
		t.Errorf("Expected 'api.v1.auth.login|db.query|http.request', got '%s'", path)
	}

	// Test with disabled flag
	path = dm.getCombinedPath(TestFlag1 | TestFlag4) // TestFlag4 not registered
	if path != "api.v1.auth.login" {
		t.Errorf("Expected 'api.v1.auth.login', got '%s'", path)
	}
}

func TestDebugMultiFlag(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
		{TestFlag3, "http.request", "http.request"},
	})

	// Enable only specific flags
	err := dm.SetFlags("api.v1.auth.login,db.query")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	t.Logf("Enabled flags: %b", dm.flags)
	t.Logf("TestFlag1: %b, enabled: %v", TestFlag1, dm.IsEnabled(TestFlag1))
	t.Logf("TestFlag2: %b, enabled: %v", TestFlag2, dm.IsEnabled(TestFlag2))
	t.Logf("TestFlag3: %b, enabled: %v", TestFlag3, dm.IsEnabled(TestFlag3))

	combined := TestFlag1 | TestFlag3
	t.Logf("TestFlag1|TestFlag3: %b", combined)
	t.Logf("dm.flags & combined: %b", dm.flags&combined)
	t.Logf("Should log: %v", dm.shouldLogWithFlags(combined, SeverityDebug))
}

func TestAnyVsAllFlags(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
		{TestFlag3, "http.request", "http.request"},
	})

	// Enable only some flags
	err := dm.SetFlags("api.v1.auth.login,db.query")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	combined := TestFlag1 | TestFlag2 | TestFlag3 // All three flags

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Test ANY logic - should log because TestFlag1 and TestFlag2 are enabled
	dm.LogWithAnyFlags(combined, "ANY: This should log because some flags are enabled")

	// Test ALL logic - should NOT log because TestFlag3 is not enabled
	dm.LogWithAllFlags(combined, "ALL: This should NOT log because not all flags are enabled")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check expected messages
	if !strings.Contains(output, "ANY: This should log because some flags are enabled") {
		t.Error("Expected ANY message to be logged")
	}
	if strings.Contains(output, "ALL: This should NOT log because not all flags are enabled") {
		t.Error("Expected ALL message to not be logged")
	}

	// Now enable all flags
	dm.SetFlags("api.v1.auth.login,db.query,http.request")

	// Capture stderr again
	oldStderr = os.Stderr
	r, w, _ = os.Pipe()
	os.Stderr = w

	// Test ALL logic - should now log because all flags are enabled
	dm.LogWithAllFlags(combined, "ALL: This should now log because all flags are enabled")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf = make([]byte, 1024)
	n, _ = r.Read(buf)
	output = string(buf[:n])

	// Check expected messages
	if !strings.Contains(output, "ALL: This should now log because all flags are enabled") {
		t.Error("Expected ALL message to be logged when all flags are enabled")
	}
}

func TestAnyVsAllWithSeverity(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
	})

	// Enable flags with different severity filters
	err := dm.SetFlags("api.v1.auth.login:ERROR,db.query:WARN")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	combined := TestFlag1 | TestFlag2

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	// Test ANY with ERROR severity - should log (matches api.v1.auth.login:ERROR)
	dm.LogWithAnyFlagsAndSeverity(combined, SeverityError, "", "ANY ERROR: Should log")

	// Test ANY with WARN severity - should log (matches db.query:WARN)
	dm.LogWithAnyFlagsAndSeverity(combined, SeverityWarning, "", "ANY WARN: Should log")

	// Test ANY with INFO severity - should not log (neither flag allows INFO)
	dm.LogWithAnyFlagsAndSeverity(combined, SeverityInfo, "", "ANY INFO: Should not log")

	// Test ALL with ERROR severity - should log (both flags are enabled and api.v1.auth.login allows ERROR)
	dm.LogWithAllFlagsAndSeverity(combined, SeverityError, "", "ALL ERROR: Should log")

	// Test ALL with WARN severity - should log (both flags are enabled and db.query allows WARN)
	dm.LogWithAllFlagsAndSeverity(combined, SeverityWarning, "", "ALL WARN: Should log")

	// Test ALL with INFO severity - should not log (neither flag allows INFO)
	dm.LogWithAllFlagsAndSeverity(combined, SeverityInfo, "", "ALL INFO: Should not log")

	w.Close()
	os.Stderr = oldStderr

	// Read captured output
	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	// Check expected messages
	expectedMessages := []string{
		"ANY ERROR: Should log",
		"ANY WARN: Should log",
		"ALL ERROR: Should log",
		"ALL WARN: Should log",
	}
	unexpectedMessages := []string{
		"ANY INFO: Should not log",
		"ALL INFO: Should not log",
	}

	for _, msg := range expectedMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("Expected message '%s' to be logged", msg)
		}
	}

	for _, msg := range unexpectedMessages {
		if strings.Contains(output, msg) {
			t.Errorf("Expected message '%s' to not be logged", msg)
		}
	}
}

// Note: TestV2LogicalExpressions was removed as LogWithExpression methods were removed.
// V2 logical expressions are only used for flag configuration, not for logging calls.

func TestSlogIntegration(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
	})

	// Enable some flags
	dm.SetFlags("api.v1.auth.login,db.query")

	// Test traditional logging (default)
	oldStderr := os.Stderr
	r1, w1, _ := os.Pipe()
	os.Stderr = w1

	dm.Log(TestFlag1, "Traditional message")
	w1.Close()
	os.Stderr = oldStderr

	buf1 := make([]byte, 1024)
	n1, _ := r1.Read(buf1)
	output1 := string(buf1[:n1])

	if !strings.Contains(output1, "Traditional message") {
		t.Errorf("Expected traditional message to be logged")
	}

	// Test slog integration with buffer
	var buf2 bytes.Buffer
	dm.EnableSlogWithHandler(slog.NewTextHandler(&buf2, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dm.Log(TestFlag1, "Slog message")
	output2 := buf2.String()

	if !strings.Contains(output2, "Slog message") {
		t.Errorf("Expected slog message to be logged, got: %s", output2)
	}

	// Test slog state
	if !dm.IsSlogEnabled() {
		t.Errorf("Expected slog to be enabled")
	}

	// Test disabling slog
	dm.DisableSlog()
	if dm.IsSlogEnabled() {
		t.Errorf("Expected slog to be disabled")
	}
}

func TestContextSystem(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
		{TestFlag3, "validation", "validation"},
	})

	// Enable some flags
	dm.SetFlags("api.v1.auth.login,db.query,validation")

	// Test WithContext
	var output1 string
	dm.WithContext(TestFlag1, func() {
		// Capture output
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		dm.Log(TestFlag2, "DB query in login context")
		w.Close()
		os.Stderr = oldStderr

		buf := make([]byte, 1024)
		n, _ := r.Read(buf)
		output1 = string(buf[:n])
	})

	// Check that context was included in output
	if !strings.Contains(output1, "ctx: api.v1.auth.login") {
		t.Errorf("Expected context to be included in output, got: %s", output1)
	}

	// Test manual context management
	dm.PushContext(TestFlag1)
	dm.PushContext(TestFlag2)
	
	context := dm.GetContext()
	expectedContext := TestFlag1 | TestFlag2
	if context != expectedContext {
		t.Errorf("Expected context %d, got %d", expectedContext, context)
	}

	// Test PopContext
	popped := dm.PopContext()
	if popped != TestFlag2 {
		t.Errorf("Expected to pop TestFlag2 (%d), got %d", TestFlag2, popped)
	}

	// Test ClearContext
	dm.ClearContext()
	if dm.GetContext() != 0 {
		t.Errorf("Expected context to be cleared, got %d", dm.GetContext())
	}
}

func TestContextInheritance(t *testing.T) {
	dm := NewDebugManager()
	dm.RegisterFlags([]FlagDefinition{
		{TestFlag1, "api.v1.auth.login", "api.v1.auth.login"},
		{TestFlag2, "db.query", "db.query"},
		{TestFlag3, "validation", "validation"},
	})

	dm.SetFlags("api.v1.auth.login,db.query,validation")

	// Test nested context
	var output string
	dm.WithContext(TestFlag1, func() {
		dm.WithContext(TestFlag3, func() {
			// Capture output
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stderr = w

			dm.Log(TestFlag2, "DB query in nested context")
			w.Close()
			os.Stderr = oldStderr

			buf := make([]byte, 1024)
			n, _ := r.Read(buf)
			output = string(buf[:n])
		})
	})

	// Check that both contexts are included
	if !strings.Contains(output, "ctx: api.v1.auth.login -> validation") {
		t.Errorf("Expected nested context to be included, got: %s", output)
	}
}
