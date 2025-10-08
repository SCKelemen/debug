package debug

import (
	"log/slog"
	"os"
	"sync"
)

// FlagParser defines the interface for parsing debug flag strings
type FlagParser interface {
	// ParseFlags parses a flag string and returns the enabled flags and path severity filters
	ParseFlags(flags string, flagMap map[string]DebugFlag, pathMap map[DebugFlag]string) (DebugFlag, []PathSeverityFilter, error)
}

// DebugManager manages debug flags and output with pluggable parsing
type DebugManager struct {
	mu                  sync.RWMutex // Protects all fields below
	flags               DebugFlag
	severityFilter      Severity
	pathFilters         []string
	pathSeverityFilters []PathSeverityFilter
	globEnabled         bool
	flagMap             map[string]DebugFlag
	pathMap             map[DebugFlag]string
	allFlags            []DebugFlag
	logger              *slog.Logger // nil means use traditional logging
	parser              FlagParser   // Parser for flag strings
}

// NewDebugManager creates a new debug manager with traditional logging
func NewDebugManager(parser FlagParser) *DebugManager {
	return &DebugManager{
		flags:               0,
		severityFilter:      SeverityTrace, // Show all by default
		pathFilters:         []string{},
		pathSeverityFilters: []PathSeverityFilter{},
		globEnabled:         true,
		flagMap:             make(map[string]DebugFlag),
		pathMap:             make(map[DebugFlag]string),
		allFlags:            []DebugFlag{},
		logger:              nil, // Traditional logging
		parser:              parser,
	}
}

// NewDebugManagerWithSlog creates a new debug manager with slog integration
func NewDebugManagerWithSlog(parser FlagParser) *DebugManager {
	return &DebugManager{
		flags:               0,
		severityFilter:      SeverityTrace, // Show all by default
		pathFilters:         []string{},
		pathSeverityFilters: []PathSeverityFilter{},
		globEnabled:         true,
		flagMap:             make(map[string]DebugFlag),
		pathMap:             make(map[DebugFlag]string),
		allFlags:            []DebugFlag{},
		logger:              slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		parser:              parser,
	}
}

// NewDebugManagerWithSlogHandler creates a new debug manager with custom slog handler
func NewDebugManagerWithSlogHandler(parser FlagParser, handler slog.Handler) *DebugManager {
	return &DebugManager{
		flags:               0,
		severityFilter:      SeverityTrace, // Show all by default
		pathFilters:         []string{},
		pathSeverityFilters: []PathSeverityFilter{},
		globEnabled:         true,
		flagMap:             make(map[string]DebugFlag),
		pathMap:             make(map[DebugFlag]string),
		allFlags:            []DebugFlag{},
		logger:              slog.New(handler),
		parser:              parser,
	}
}
