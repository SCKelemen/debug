# Debug Library Design Review & Evolution Plan

## Executive Summary

This document reviews the current debug library architecture, identifies limitations (particularly the 64-bit flag constraint), and proposes solutions for scaling to large systems while maintaining fast evaluation and integrating with the lifecycle events system.

## Current Architecture

### Core Components

1. **DebugFlag**: `uint64` type using bitflags (`1 << iota`)
   - **Limitation**: Maximum 64 flags per system
   - **Advantage**: O(1) evaluation with bitwise operations (`enabledFlags & flag != 0`)

2. **Two Parser Implementations**:
   - **v1 Parser**: Simple, lightweight - handles comma-separated flags and glob patterns
   - **v2 Parser**: More powerful - supports logical expressions (`|`, `&`, `!`, `()`), plus all v1 features
   - **Note**: These are parser variants, not API versions. Both use the same `DebugManager` and `DebugFlag` type.

3. **Hierarchical Path System**:
   - Dot notation: `api.v1.auth.login`, `db.user.query`, `http.request`
   - Glob pattern matching: `api.*`, `db.**`, `api.v1.auth.*`
   - Path-based severity filtering: `api.v1.*:ERROR`, `db.*:+WARN`

4. **Fast Evaluation**:
   - Bitwise operations for flag checking: `O(1)`
   - Glob pattern matching only when patterns are used
   - Path severity filters checked after flag match

### Current Strengths

✅ **Super fast evaluation** - O(1) bitwise operations  
✅ **Hierarchical organization** - Dot notation paths  
✅ **Flexible configuration** - Glob patterns, logical expressions (v2)  
✅ **Severity filtering** - Path-based and global  
✅ **Slog integration** - Structured logging support  
✅ **Method contexts** - Clean API for method-scoped logging  

### Current Limitations

❌ **64 flag maximum** - `uint64` constraint  
❌ **No integration with lifecycle events** - Separate systems  
❌ **No PII awareness** - Doesn't leverage schema annotations  
❌ **Limited scalability** - Can't handle large microservice ecosystems  

## Problem Statement

For large systems with many services, APIs, and operations, 64 flags are insufficient. We need:

1. **Unlimited flags** while maintaining fast evaluation
2. **Hierarchical path preservation** (dot notation)
3. **Integration with lifecycle events** for unified observability
4. **PII awareness** using schema annotations from API generator
5. **Tooling** for developers to easily enable/disable debug logs

## Proposed Solutions

### Solution 1: Path-Based Flag System (Recommended)

Instead of bitflags, use a **hierarchical path-based system** with fast lookup structures.

#### Architecture

```go
// Path-based flag system
type PathFlagManager struct {
    // Fast lookup: path -> enabled state
    enabledPaths map[string]bool
    
    // Pattern cache: compiled glob patterns -> matching paths
    patternCache map[string][]string
    
    // Hierarchical tree for fast parent/child lookups
    pathTree *PathTree
}

type PathTree struct {
    path     string
    enabled  bool
    children map[string]*PathTree
}
```

#### Evaluation Strategy

1. **Direct path lookup**: `O(1)` map lookup for exact paths
2. **Hierarchical inheritance**: Check parent paths (e.g., `api.v1.auth.login` inherits from `api.v1.auth.*`)
3. **Pattern matching**: Cache compiled patterns for fast glob matching
4. **Lazy evaluation**: Only compile patterns when first used

#### Performance Characteristics

- **Best case**: O(1) for exact path matches
- **Worst case**: O(depth) for hierarchical checks (typically 3-5 levels)
- **Pattern matching**: O(1) after cache warmup, O(n) first time (n = number of paths)

#### Example Usage

```go
// Register paths (no bitflags needed)
dm.RegisterPath("api.v1.auth.login")
dm.RegisterPath("api.v1.auth.logout")
dm.RegisterPath("db.user.query")

// Enable via patterns (same API as before)
dm.SetFlags("api.v1.*|db.user.*")

// Check if enabled (still fast)
if dm.IsEnabled("api.v1.auth.login") {
    // Log
}
```

### Solution 2: Hybrid Bitflag + Path System

Keep bitflags for common flags (< 64), use path-based for everything else.

#### Architecture

```go
type HybridFlagManager struct {
    // Bitflags for first 64 common flags (fast path)
    commonFlags    DebugFlag  // uint64
    enabledCommon  DebugFlag  // uint64
    
    // Path-based for everything else
    pathManager    *PathFlagManager
}
```

#### Evaluation Strategy

1. Check if flag is in common set (< 64): Use bitwise operations (O(1))
2. Otherwise: Use path-based lookup (O(1) to O(depth))

#### Performance Characteristics

- **Common flags**: O(1) bitwise operations (same as current)
- **Extended flags**: O(1) to O(depth) path lookup
- **Backward compatible**: Existing code using bitflags continues to work

### Solution 3: Multi-Word Bitflags

Extend to multiple uint64 words for more flags.

#### Architecture

```go
type MultiWordFlag struct {
    words []uint64  // Each word = 64 flags
}

// Example: 128 flags = 2 words, 256 flags = 4 words, etc.
```

#### Evaluation Strategy

- Check which word contains the flag: `wordIndex = flagIndex / 64`
- Use bitwise operations on that word: `words[wordIndex] & (1 << (flagIndex % 64))`

#### Performance Characteristics

- **Evaluation**: O(1) - still fast, just one extra array index
- **Memory**: Linear growth (64 flags per word)
- **Scalability**: Can scale to thousands of flags

#### Limitations

- Still requires pre-registration of all flags
- Less flexible than path-based system
- Doesn't leverage hierarchical structure

## Recommended Approach: Path-Based System

### Why Path-Based?

1. **Unlimited scalability** - No hard limit on number of flags
2. **Natural hierarchy** - Dot notation paths are already hierarchical
3. **Flexible registration** - Flags can be registered dynamically
4. **Pattern-friendly** - Glob patterns work naturally with paths
5. **Future-proof** - Easy to extend with new features

### Performance Optimization Strategies

1. **Path Tree Caching**: Build a tree structure for O(depth) hierarchical checks
2. **Pattern Compilation**: Compile glob patterns to regex or trie structures
3. **Hot Path Optimization**: Cache frequently checked paths
4. **Lazy Evaluation**: Only compile patterns when first used

### Implementation Plan

#### Phase 1: Path-Based Core
- [ ] Implement `PathFlagManager` with map-based lookup
- [ ] Add hierarchical path inheritance
- [ ] Implement glob pattern matching with caching
- [ ] Maintain backward compatibility with existing API

#### Phase 2: Performance Optimization
- [ ] Build path tree for faster hierarchical checks
- [ ] Implement pattern compilation cache
- [ ] Add hot path optimization
- [ ] Benchmark and optimize critical paths

#### Phase 3: Lifecycle Integration
- [ ] Integrate with lifecycle events library
- [ ] Add PII awareness using schema annotations
- [ ] Create unified logging interface
- [ ] Build developer tooling

## Integration with Lifecycle Events

### Unified Logging Strategy

The debug library and lifecycle events should work together:

1. **Debug logs** → For detailed, on-demand debugging (controlled by flags)
2. **Lifecycle events** → For structured observability (always emitted, PII-redacted)

### Integration Points

```go
// Debug logs (conditional, detailed)
if dm.IsEnabled("api.v1.user.create") {
    dm.Log("api.v1.user.create", "Creating user with email: %s", email)
}

// Lifecycle events (always, structured, PII-safe)
producer.EmitRequestReceived(ctx, api, correlationID, method, path, userAgent, remoteAddr, nil)
producer.EmitResourceCreated(ctx, api, correlationID, actor, resource, data, schemaAnnotations, nil)
```

### Combined Interface

```go
type UnifiedLogger struct {
    debug    *DebugManager
    lifecycle *lifecycle.Producer
}

func (l *UnifiedLogger) Debug(path string, msg string, args ...interface{}) {
    // Check debug flag first
    if l.debug.IsEnabled(path) {
        l.debug.Log(path, msg, args...)
    }
    
    // Always emit lifecycle event (with PII redaction)
    l.lifecycle.EmitDebugEvent(ctx, path, msg, args...)
}
```

### PII Integration

Use schema annotations from API generator:

```go
// Debug logs respect PII annotations
dm.LogWithData("api.v1.user.create", userData, schemaAnnotations)

// Lifecycle events automatically redact PII
producer.EmitResourceCreated(ctx, api, correlationID, actor, resource, userData, schemaAnnotations, nil)
```

## Developer Tooling

### CLI Tools

1. **Flag Discovery**: `debug list` - Show all available flags
2. **Flag Testing**: `debug test "api.v1.*"` - Test which flags match
3. **Pattern Helper**: `debug match "api.v1.*"` - Show matching paths
4. **Integration**: `debug enable "api.v1.*|db.*"` - Set flags via CLI

### IDE Integration

1. **Autocomplete**: Suggest available flags in code
2. **Flag Usage**: Show where flags are used
3. **Pattern Validation**: Validate glob patterns at compile time

### Runtime Tools

1. **Dynamic Flag Control**: HTTP endpoint to enable/disable flags at runtime
2. **Flag Analytics**: Track which flags are most used
3. **Performance Monitoring**: Track evaluation performance

## Migration Strategy

### Backward Compatibility

1. **Keep existing API**: `DebugFlag` type and bitwise operations
2. **Add new API**: Path-based methods alongside existing ones
3. **Gradual migration**: Services can migrate at their own pace
4. **Deprecation path**: Mark bitflag API as deprecated, provide migration guide

### Example Migration

```go
// Old way (still works)
const DebugHTTPRequest = DebugFlag(1 << 0)
dm.RegisterFlags([]FlagDefinition{
    {Flag: DebugHTTPRequest, Name: "http.request", Path: "http.request"},
})
dm.SetFlags("http.request")

// New way (recommended)
dm.RegisterPath("http.request")
dm.SetFlags("http.request")

// Both work together during transition
```

## Performance Benchmarks

### Target Performance

- **Flag check**: < 100ns (comparable to current bitwise operations)
- **Pattern matching**: < 1μs (first time), < 100ns (cached)
- **Hierarchical check**: < 500ns (for 5-level deep paths)

### Benchmarking Plan

1. Compare path-based vs bitflag performance
2. Measure pattern compilation overhead
3. Test hierarchical lookup performance
4. Profile real-world usage patterns

## Next Steps

1. **Review this design** with the team
2. **Prototype path-based system** to validate performance
3. **Benchmark** against current bitflag system
4. **Implement** path-based core if benchmarks are acceptable
5. **Integrate** with lifecycle events library
6. **Build** developer tooling
7. **Migrate** existing services gradually

## Open Questions

1. **Performance threshold**: What's acceptable performance degradation for unlimited flags?
2. **Migration timeline**: How quickly should we migrate existing services?
3. **Tooling priority**: Which developer tools are most important?
4. **PII integration**: How deep should PII awareness go in debug logs?
5. **Pattern complexity**: Should we support more complex patterns (regex, etc.)?

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Author**: Design Review


