package debug

// FlagParser defines the interface for parsing debug flag strings
type FlagParser interface {
	// ParseFlags parses a flag string and returns the enabled flags and path severity filters
	// Note: pathMap parameter is kept for backward compatibility but is not used (slices can't be map keys).
	// Parsers should use flagMap keys (which are paths) for glob pattern matching instead.
	ParseFlags(flags string, flagMap map[string]DebugFlag, pathMap interface{}) (DebugFlag, []PathSeverityFilter, error)
}
