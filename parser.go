package debug

// FlagParser defines the interface for parsing debug flag strings
type FlagParser interface {
	// ParseFlags parses a flag string and returns the enabled flags and path severity filters
	ParseFlags(flags string, flagMap map[string]DebugFlag, pathMap map[DebugFlag]string) (DebugFlag, []PathSeverityFilter, error)
}
