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

#### Example Usage (Old Path-Based Only - For Reference)

```go
// This was the pure path-based approach
// Now we use hybrid: first 64 get bitflags automatically
dm.RegisterPath("api.v1.auth.login")      // Would use path tree
dm.RegisterPath("api.v1.auth.logout")    // Would use path tree
dm.RegisterPath("db.user.query")          // Would use path tree

// Enable via patterns (same API as before)
dm.SetFlags("api.v1.*|db.user.*")

// Check if enabled (path tree lookup)
if dm.IsEnabled("api.v1.auth.login") {
    // Log
}
```

### Solution 2: Hybrid Bitflag + Path System (Recommended)

Automatically use bitflags for the most common flags in each service, with path-based lookup for everything else. All flags maintain dot-pathed names - the manager transparently handles the optimization.

#### Architecture

```go
type HybridFlagManager struct {
    // Bitflags for common flags (first 64 registered per service)
    commonFlags    map[string]DebugFlag  // path -> bitflag
    bitflagMap     map[DebugFlag]string  // bitflag -> path (reverse lookup)
    enabledFlags   DebugFlag             // uint64 - enabled common flags
    
    // Path-based for uncommon flags (beyond first 64)
    pathTree       *PathTree             // Cached tree for fast lookup
    enabledPaths   map[string]bool       // Fast lookup for enabled paths
    
    // Automatic assignment tracking
    nextBitFlag    int                   // Next available bitflag (0-63)
    maxCommonFlags int                   // Max common flags (default: 64)
}
```

#### Automatic Flag Assignment

The manager automatically assigns bitflags to the first N registered flags (default: 64) based on registration order. This means:
- **First 64 registered paths** → Get bitflags automatically (O(1) evaluation)
- **All other paths** → Use cached tree lookup (O(1) to O(depth))
- **Same API** → Developers don't need to think about which is which

**Registration Strategy:**
```go
func (h *HybridFlagManager) RegisterPath(path string) {
    if h.nextBitFlag < h.maxCommonFlags {
        // Assign bitflag to this path
        flag := DebugFlag(1 << h.nextBitFlag)
        h.commonFlags[path] = flag
        h.bitflagMap[flag] = path
        h.nextBitFlag++
    } else {
        // Add to path tree
        h.pathTree.Add(path)
    }
}
```

**Cached Tree Lookup:**
The path tree is built once and cached, providing fast hierarchical lookups:
- Direct path match: O(1) map lookup
- Hierarchical inheritance: O(depth) tree traversal (typically 3-5 levels)
- Pattern matching: O(1) after compilation, cached for reuse

#### Evaluation Strategy

```go
func (h *HybridFlagManager) IsEnabled(path string) bool {
    // Fast path: Check if path has a bitflag
    if flag, hasBitFlag := h.commonFlags[path]; hasBitFlag {
        return h.enabledFlags & flag != 0  // O(1) bitwise operation
    }
    
    // Slow path: Use cached tree lookup
    return h.pathTree.IsEnabled(path)  // O(1) to O(depth)
}
```

#### Performance Characteristics

- **Common flags (first 64)**: O(1) bitwise operations (same as current system)
- **Extended flags**: O(1) to O(depth) cached tree lookup
- **Transparent optimization**: Developers use same API, manager handles optimization
- **Backward compatible**: Existing bitflag code continues to work
- **Service-specific**: Each service can have its own 64 common flags

#### Example Usage

```go
// Register flags - first 64 automatically get bitflags
dm.RegisterPath("api.v1.auth.login")      // Gets bitflag 1 << 0
dm.RegisterPath("api.v1.auth.logout")     // Gets bitflag 1 << 1
dm.RegisterPath("db.user.query")          // Gets bitflag 1 << 2
// ... up to 64 flags get bitflags

dm.RegisterPath("api.v1.user.create")      // Flag 65+ uses path tree
dm.RegisterPath("api.v1.user.update")     // Flag 65+ uses path tree

// Enable via patterns (works for both)
dm.SetFlags("api.v1.*|db.user.*")

// Check if enabled (manager automatically uses fastest method)
if dm.IsEnabled("api.v1.auth.login") {    // Uses bitflag (O(1))
    // Log
}

if dm.IsEnabled("api.v1.user.create") {   // Uses path tree (O(1) to O(depth))
    // Log
}
```

#### Benefits

1. **Best of both worlds**: Fast bitflags for hot paths, unlimited scalability for everything else
2. **Zero developer overhead**: Same API, automatic optimization
3. **Service-optimized**: Each service's most common flags get bitflags
4. **Backward compatible**: Existing code using bitflags continues to work
5. **Natural evolution**: Services can register flags in order of importance

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

## Recommended Approach: Hybrid Bitflag + Path System

### Why Hybrid?

1. **Best performance for common cases** - O(1) bitwise operations for first 64 flags per service
2. **Unlimited scalability** - Path-based system handles everything beyond 64
3. **Transparent optimization** - Developers use same API, manager handles the rest
4. **Service-optimized** - Each service's most common flags automatically get bitflags
5. **Backward compatible** - Existing bitflag code continues to work unchanged
6. **Natural hierarchy** - Dot notation paths work for both bitflags and path-based
7. **Pattern-friendly** - Glob patterns work seamlessly across both systems

### Performance Optimization Strategies

1. **Automatic Bitflag Assignment**: First 64 registered paths per service get bitflags
2. **Cached Path Tree**: Build a tree structure for O(1) to O(depth) hierarchical checks
3. **Pattern Compilation**: Compile glob patterns to regex or trie structures
4. **Hot Path Optimization**: Cache frequently checked paths
5. **Lazy Evaluation**: Only compile patterns when first used
6. **Service Isolation**: Each service can have its own set of 64 common flags

### Implementation Plan

#### Phase 1: Hybrid Core
- [ ] Implement automatic bitflag assignment for first 64 registered paths
- [ ] Build path tree for flags beyond 64
- [ ] Add hierarchical path inheritance for both systems
- [ ] Implement glob pattern matching with caching (works for both)
- [ ] Maintain backward compatibility with existing bitflag API
- [ ] Add transparent evaluation that chooses fastest method

#### Phase 2: Performance Optimization
- [ ] Optimize path tree lookup (cache frequently accessed paths)
- [ ] Implement pattern compilation cache
- [ ] Add hot path optimization (track and optimize most-used paths)
- [ ] Benchmark bitflag vs path tree performance
- [ ] Consider dynamic promotion: promote frequently-used path flags to bitflags

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


