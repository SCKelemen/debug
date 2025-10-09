# Debug Package Examples

This directory contains examples demonstrating how to use the debug package with context-based logging.

## Examples Overview

### 1. Basic Examples
- **`basic/`** - Comprehensive example showing both V1 and V2 parsers with various features
- **`comparison/`** - Side-by-side comparison of V1 vs V2 parser capabilities
- **`v1-simple/`** - Simple V1 parser example with comma-separated flags
- **`v2-features/`** - V2 parser example with logical expressions and slog integration

### 2. Context-Based Examples
- **`context-http/`** - HTTP handler example with context marking for requests and database calls
- **`context-middleware/`** - Middleware example showing context flow through authentication and logging
- **`context-functions/`** - Function-level context marking with automatic entry/exit logging
- **`context-stacking/`** - Context inheritance example following standard Go context patterns

## Running the Examples

### Basic Examples
```bash
# Run basic comprehensive example
go run examples/basic/main.go

# Run V1 vs V2 comparison
go run examples/comparison/main.go

# Run V1 simple example
go run examples/v1-simple/main.go

# Run V2 features example
go run examples/v2-features/main.go
```

### Context-Based Examples
```bash
# Run HTTP handler with context marking
go run examples/context-http/main.go

# Run middleware with context flow
go run examples/context-middleware/main.go

# Run function-level context marking
go run examples/context-functions/main.go

# Run context inheritance example
go run examples/context-stacking/main.go
```

## Context-Based Logging Benefits

The context-based examples demonstrate several key benefits:

### 1. Function Entry/Exit Marking
- Set context at function entry points
- Context flows through the call stack
- Each function can add its own debug flags
- Automatic cleanup with defer statements

### 2. HTTP Request Tracing
- Middleware adds context at request entry
- Context flows through entire request lifecycle
- Each service can add its own debug flags
- Complete request flow visibility

### 3. Hierarchical Function Tracing
- Automatic function entry/exit logging
- Error handling with context
- Each function can have its own debug flag
- Easy to trace complex call chains

### 4. Context Inheritance
- Context flags are immutable and inherited
- Follows standard Go context patterns
- Child functions inherit parent context
- Selective logging based on context inheritance

## Key Patterns Demonstrated

### Context Marking Pattern
```go
// Mark function in context at entry
ctx = debug.WithDebugFlags(ctx, debug.DebugFlag(1<<0))

// Log with context
dm.Log(ctx, 1<<0, "Processing request")

// Context flows to called functions
otherFunction(ctx, dm)
```

### Middleware Pattern
```go
func AuthMiddleware(dm *debug.DebugManager, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Mark middleware in context
        ctx := debug.WithDebugFlags(r.Context(), debug.DebugFlag(1<<3))
        
        // Log middleware activity
        dm.Log(ctx, 1<<3, "Authentication middleware processing")
        
        // Pass context to next handler
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### Function Context Pattern
```go
func ProcessUser(ctx context.Context, dm *debug.DebugManager) error {
    // Mark function in context
    ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<5), "ProcessUser")
    defer fc.Cleanup()
    
    // Function logic here
    return nil
}
```

### Context Inheritance Pattern
```go
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()
    
    // Add API context - inherited by child functions
    ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<3), "api.v1.auth.login", h.dm)
    
    // Add HTTP context
    ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<0), "http.request", h.dm)
    
    // Database calls inherit both contexts
    user, err := h.db.GetUser(ctx, userID)
}
```

## Debug Flag Configuration

All examples use a consistent set of debug flags:

```go
flagDefs := []debug.FlagDefinition{
    {Flag: 1 << 0, Name: "http.request", Path: "http.request"},
    {Flag: 1 << 1, Name: "http.response", Path: "http.response"},
    {Flag: 1 << 2, Name: "db.query", Path: "db.query"},
    {Flag: 1 << 3, Name: "auth.middleware", Path: "auth.middleware"},
    {Flag: 1 << 4, Name: "cache.redis", Path: "cache.redis"},
    // ... more flags
}
```

## Output Format

The examples use JSON logging for structured output:

```json
{
  "time": "2025-10-09T13:26:35.590181+02:00",
  "level": "DEBUG",
  "msg": "Processing HTTP GET request to /users/123",
  "flag": "http.request (ctx: http.request)",
  "severity": "DEBUG"
}
```

The `flag` field shows both the current flag and the context flags, making it easy to trace the flow of context through the application.
