# Debug - A Flexible Debug Flag System for Go

A powerful and flexible debug flag system for Go applications that supports hierarchical flag organization, glob pattern matching, and severity-based filtering.

## Features

- **Bitflag-based**: Efficient flag management using bitwise operations
- **Hierarchical Organization**: Organize flags into logical trees (e.g., `http.request`, `db.query`)
- **Glob Pattern Matching**: Enable multiple flags using patterns like `http.*` or `db.*`
- **Severity Filtering**: Control output based on message severity levels
- **Context Support**: Add contextual information to debug messages
- **Flexible Registration**: Register custom flags for your application
- **Zero Dependencies**: Pure Go implementation with no external dependencies

## Installation

```bash
go get github.com/SCKelemen/debug
```

## Quick Start

```go
package main

import (
    "github.com/SCKelemen/debug"
)

// Define your debug flags
const (
    DebugHTTPRequest  debug.DebugFlag = 1 << iota
    DebugHTTPResponse
    DebugDBQuery
    DebugValidation
)

func main() {
    // Create debug manager
    dm := debug.NewDebugManager()
    
    // Register flags
    dm.RegisterFlags([]debug.FlagDefinition{
        {DebugHTTPRequest, "http.request", "http.request"},
        {DebugHTTPResponse, "http.response", "http.response"},
        {DebugDBQuery, "db.query", "db.query"},
        {DebugValidation, "validation", "validation"},
    })
    
    // Enable flags using glob patterns
    dm.SetFlags("http.*,db.query")
    
    // Log debug messages
    dm.Log(DebugHTTPRequest, "Processing request to /api/users")
    dm.Log(DebugDBQuery, "Executing SELECT * FROM users")
}
```

## API Reference

### DebugManager

The main type for managing debug flags and output.

#### Constructor

```go
func NewDebugManager() *DebugManager
```

Creates a new debug manager instance.

#### Flag Registration

```go
func (dm *DebugManager) RegisterFlags(definitions []FlagDefinition)
```

Registers debug flags with the manager. Each `FlagDefinition` contains:
- `Flag`: The bitflag value
- `Name`: The flag name for string-based enabling
- `Path`: The hierarchical path for glob matching

#### Flag Management

```go
func (dm *DebugManager) SetFlags(flags string) error
```

Sets debug flags from a comma-separated string. Supports:
- Individual flags: `"http.request,db.query"`
- Glob patterns: `"http.*,db.*"`
- Special values: `"all"` or `"*"` to enable everything

```go
func (dm *DebugManager) IsEnabled(flag DebugFlag) bool
```

Checks if a specific flag is enabled.

#### Severity Filtering

```go
func (dm *DebugManager) SetSeverityFilter(severity Severity)
func (dm *DebugManager) SetSeverityFilterFromString(severity string) error
```

Sets the minimum severity level for messages. Available levels:
- `SeverityTrace` (lowest)
- `SeverityDebug`
- `SeverityInfo`
- `SeverityWarning`
- `SeverityError`
- `SeverityFatal` (highest)

#### Logging Methods

```go
func (dm *DebugManager) Log(flag DebugFlag, format string, args ...interface{})
```

Basic logging with default severity (Debug).

```go
func (dm *DebugManager) LogWithSeverity(flag DebugFlag, severity Severity, context string, format string, args ...interface{})
```

Logging with custom severity and optional context.

```go
func (dm *DebugManager) LogWithContext(flag DebugFlag, context string, format string, args ...interface{})
```

Logging with context information.

```go
func (dm *DebugManager) LogWithPath(path string, severity Severity, context string, format string, args ...interface{})
```

Logging with a custom path (useful for dynamic paths).

#### Utility Methods

```go
func (dm *DebugManager) GetEnabledFlags() []string
func (dm *DebugManager) GetAvailableFlags() []string
func (dm *DebugManager) GetFlagPath(flag DebugFlag) string
func (dm *DebugManager) GetFlagName(flag DebugFlag) string
```

## Usage Patterns

### 1. Organizing Flags by Module

```go
const (
    // HTTP module
    DebugHTTPRequest  debug.DebugFlag = 1 << iota
    DebugHTTPResponse
    DebugHTTPError
    
    // Database module
    DebugDBQuery
    DebugDBConnection
    DebugDBCache
    
    // Processing module
    DebugValidation
    DebugTransformation
    DebugSerialization
)

flagDefinitions := []debug.FlagDefinition{
    {DebugHTTPRequest, "http.request", "http.request"},
    {DebugHTTPResponse, "http.response", "http.response"},
    {DebugHTTPError, "http.error", "http.error"},
    {DebugDBQuery, "db.query", "db.query"},
    {DebugDBConnection, "db.connection", "db.connection"},
    {DebugDBCache, "db.cache", "db.cache"},
    {DebugValidation, "validation", "validation"},
    {DebugTransformation, "transformation", "transformation"},
    {DebugSerialization, "serialization", "serialization"},
}
```

### 2. Using Glob Patterns

```go
// Enable all HTTP-related flags
dm.SetFlags("http.*")

// Enable all database flags
dm.SetFlags("db.*")

// Enable multiple patterns
dm.SetFlags("http.*,db.query,validation")

// Enable everything
dm.SetFlags("all")
```

### 3. Severity-Based Filtering

```go
// Only show warnings and errors
dm.SetSeverityFilter(debug.SeverityWarning)

// Or set from string
dm.SetSeverityFilterFromString("warning")
```

### 4. Contextual Logging

```go
dm.LogWithContext(DebugHTTPRequest, "user-service", "Processing request for user ID: %d", userID)
dm.LogWithSeverity(DebugDBQuery, debug.SeverityError, "database", "Query failed: %v", err)
```

### 5. Dynamic Path Logging

```go
dm.LogWithPath("custom.module.submodule", debug.SeverityInfo, "context", "Custom message")
```

## Advanced Features

### Glob Pattern Matching

The system supports standard glob patterns:
- `*` matches any characters except path separators
- `**` matches any characters including path separators
- `?` matches any single character

Examples:
- `http.*` matches `http.request`, `http.response`, but not `http.api.request`
- `http.**` matches `http.request`, `http.api.request`, `http.api.v1.request`
- `db.*.query` matches `db.user.query`, `db.product.query`

### Performance Considerations

- Flag checking uses bitwise operations for maximum performance
- Glob pattern matching is only performed when patterns are used
- Severity filtering is applied before any other checks
- Path filters are only checked when glob patterns are enabled

### Thread Safety

The `DebugManager` is not thread-safe by design. If you need thread-safe access, wrap it with appropriate synchronization primitives or create separate instances per goroutine.

## Examples

See the `example/` directory for complete working examples demonstrating various usage patterns.

---

**Note**: This is a private prototype library for internal use only.

