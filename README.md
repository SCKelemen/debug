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
- **Path-based severity filtering**: `"path:SEVERITY"` syntax for fine-grained control

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

### 3. Path-Based Severity Filtering

The debug system supports sophisticated severity filtering per path, allowing you to control exactly which severity levels are shown for different parts of your application.

#### Syntax Options

| Syntax | Description | Example |
|--------|-------------|---------|
| `path:SEVERITY` | Only show specific severity | `http.request:ERROR` |
| `path:+SEVERITY` | Show severity and above | `db.*:+WARN` |
| `path:SEVERITY+` | Show severity and above (alternative) | `validation:INFO+` |
| `path:SEVERITY1\|SEVERITY2` | Show multiple specific severities | `auth:ERROR\|INFO` |

#### Examples

```go
// Only show ERROR messages for HTTP requests
dm.SetFlags("http.request:ERROR")

// Show WARN and above for all database operations
dm.SetFlags("db.*:+WARN")

// Show only INFO and ERROR for validation (skip DEBUG, WARN)
dm.SetFlags("validation:INFO|ERROR")

// Mix different patterns
dm.SetFlags("http.*:ERROR,db.*:+WARN,validation:INFO|ERROR")

// Use with glob patterns
dm.SetFlags("api.*:ERROR,service.*:+INFO,internal.*:DEBUG")
```

#### Environment Variable Usage

Perfect for configuration files and environment variables:

```bash
# Only show errors for HTTP, warnings+ for DB, all for validation
export DEBUG_FLAGS="http.*:ERROR,db.*:+WARN,validation"

# Show only errors and info for specific modules
export DEBUG_FLAGS="auth:ERROR|INFO,payment:ERROR,logging:WARN+"

# Production-like configuration
export DEBUG_FLAGS="*:ERROR"
```

### 4. Global Severity-Based Filtering

```go
// Only show warnings and errors (global filter)
dm.SetSeverityFilter(debug.SeverityWarning)

// Or set from string
dm.SetSeverityFilterFromString("warning")
```

**Note**: Global severity filtering is overridden by path-based severity filtering when both are present.

### 5. Contextual Logging

```go
dm.LogWithContext(DebugHTTPRequest, "user-service", "Processing request for user ID: %d", userID)
dm.LogWithSeverity(DebugDBQuery, debug.SeverityError, "database", "Query failed: %v", err)
```

### 6. Dynamic Path Logging

```go
dm.LogWithPath("custom.module.submodule", debug.SeverityInfo, "context", "Custom message")
```

## Advanced Features

### Filtering Priority

The debug system applies filters in the following priority order:

1. **Path-based severity filters** (highest priority)
   - If a path matches a severity filter pattern, only that filter is applied
   - Example: `http.*:ERROR` overrides global settings for HTTP paths

2. **Global severity filter** (fallback)
   - Applied when no path-specific filters match
   - Example: `dm.SetSeverityFilter(debug.SeverityWarning)`

3. **Path filters** (for glob patterns)
   - Applied when glob patterns are used without severity filters
   - Example: `http.*` enables all HTTP-related flags

### Glob Pattern Matching

The system supports standard glob patterns:
- `*` matches any characters except path separators
- `**` matches any characters including path separators
- `?` matches any single character

Examples:
- `http.*` matches `http.request`, `http.response`, but not `http.api.request`
- `http.**` matches `http.request`, `http.api.request`, `http.api.v1.request`
- `db.*.query` matches `db.user.query`, `db.product.query`

### Severity Filter Examples

```go
// Production configuration - only errors
dm.SetFlags("*:ERROR")

// Development configuration - detailed logging
dm.SetFlags("http.*:DEBUG,db.*:+WARN,validation:INFO|ERROR")

// Debugging specific module
dm.SetFlags("auth.*:TRACE,payment:ERROR")

// Mixed configuration
dm.SetFlags("api.*:ERROR,internal.*:DEBUG,external.*:+INFO")
```

### Deep Hierarchical Nesting

The debug system excels at handling deeply nested hierarchical structures, perfect for complex applications with multiple API versions, modules, and sub-modules.

#### Flag Organization Pattern

```go
const (
    // API section with proper nesting
    debugAPIStart DebugFlag = 1 << iota
    DebugAPIV1Start
    DebugAPIV1AuthStart
    DebugAPIV1AuthLogin
    DebugAPIV1AuthLogout
    DebugAPIV1AuthRenewLease
    debugAPIV1AuthEnd
    debugAPIV1End
    DebugAPIV2Start
    DebugAPIV2AuthStart
    DebugAPIV2AuthLogin
    DebugAPIV2AuthLogout
    DebugAPIV2AuthRenewLease
    debugAPIV2AuthEnd
    debugAPIV2End
    debugAPIEnd
)

// Register with hierarchical paths
flagDefinitions := []debug.FlagDefinition{
    {Flag: DebugAPIV1AuthLogin, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
    {Flag: DebugAPIV1AuthLogout, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
    {Flag: DebugAPIV2AuthLogin, Name: "api.v2.auth.login", Path: "api.v2.auth.login"},
    {Flag: DebugAPIV2AuthLogout, Name: "api.v2.auth.logout", Path: "api.v2.auth.logout"},
    // ... more flags
}
```

#### Hierarchical Glob Patterns

| Pattern | Matches | Example Paths |
|---------|---------|---------------|
| `api.*` | All API v1 operations | `api.v1.auth.login`, `api.v1.auth.logout` |
| `api.**` | All API operations (any depth) | `api.v1.auth.login`, `api.v2.auth.login` |
| `api.v1.*` | All v1 operations | `api.v1.auth.login`, `api.v1.auth.logout` |
| `api.v1.**` | All v1 operations (any depth) | `api.v1.auth.login`, `api.v1.auth.renewLease` |
| `api.v1.auth.*` | All v1 auth operations | `api.v1.auth.login`, `api.v1.auth.logout` |
| `api.**.auth.*` | All auth operations across versions | `api.v1.auth.login`, `api.v2.auth.login` |

#### Complex Configuration Examples

```go
// Enable all auth operations across all API versions
dm.SetFlags("api.**.auth.*")

// Different severity levels for different API versions
dm.SetFlags("api.v1.auth.*:ERROR,api.v2.auth.*:+WARN")

// Production configuration for microservices
dm.SetFlags("api.v1.*:ERROR,api.v2.*:ERROR,internal.*:DEBUG")

// Development debugging specific module
dm.SetFlags("api.v1.auth.*:TRACE,api.v2.auth.*:DEBUG,api.*:INFO")

// Mixed configuration with fallbacks
dm.SetFlags("api.v1.auth.*:ERROR,api.v2.auth.*:+WARN,api.*:+INFO")
```

#### Environment Variable Examples

```bash
# Production: only errors for all APIs
export DEBUG_FLAGS="api.*:ERROR"

# Development: detailed auth logging, errors for everything else
export DEBUG_FLAGS="api.**.auth.*:DEBUG,api.*:ERROR"

# Debugging: trace auth, debug API, info for everything else
export DEBUG_FLAGS="api.**.auth.*:TRACE,api.*:DEBUG,*:INFO"

# Version-specific debugging
export DEBUG_FLAGS="api.v1.*:DEBUG,api.v2.*:ERROR"
```

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

