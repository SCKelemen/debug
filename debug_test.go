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

func TestParseFlagWithSeverity(t *testing.T) {
	dm := NewDebugManager()
	
	testCases := []struct {
		input     string
		path      string
		hasFilter bool
		filterType SeverityFilterType
		severities map[Severity]bool
		minSeverity Severity
		hasError  bool
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
