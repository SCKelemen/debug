package main

import (
	"fmt"
	"log/slog"
	"os"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Static context flags
const (
	APIV1AuthLogin = debug.DebugFlag(1 << 0)  // api.v1.auth.login
	DatabaseQuery  = debug.DebugFlag(1 << 4)  // db.query
	SecurityCheck  = debug.DebugFlag(1 << 7)  // security.check
	Performance    = debug.DebugFlag(1 << 8)  // performance
	HTTPRequest    = debug.DebugFlag(1 << 9)  // http.request
	CacheRedis     = debug.DebugFlag(1 << 10) // cache.redis
)

// Mock service
type Service struct {
	dm *debug.DebugManager
}

func NewService(dm *debug.DebugManager) *Service {
	return &Service{dm: dm}
}

func (s *Service) ProcessRequest() {
	// Create method context - this persists for the entire method
	mc := s.dm.WithMethodContext(APIV1AuthLogin)

	// Basic logging
	mc.Info("Processing request")

	// Single additional flag
	mc.Debug("Security check", debug.WithFlag(SecurityCheck))

	// Multiple additional flags using variadic WithFlags
	mc.Info("Database operation", debug.WithFlags(DatabaseQuery, Performance))

	// Multiple additional flags with structured logging
	mc.Warn("Cache miss",
		debug.WithFlags(CacheRedis, Performance),
		debug.WithAttr(slog.String("cacheKey", "user:123")),
		debug.WithAttr(slog.Duration("missTime", 50)))

	// Single flag with structured logging
	mc.Info("HTTP response",
		debug.WithFlag(HTTPRequest),
		debug.WithAttr(slog.Int("statusCode", 200)),
		debug.WithAttr(slog.Duration("responseTime", 100)))

	// Multiple flags with severity override
	mc.Error("Critical error",
		debug.WithFlags(SecurityCheck, Performance),
		debug.WithSeverity(debug.SeverityError),
		debug.WithAttr(slog.String("error", "authentication_failed")))

	// Mix of single and multiple flags in different calls
	mc.Debug("Step 1", debug.WithFlag(DatabaseQuery))
	mc.Debug("Step 2", debug.WithFlags(SecurityCheck, Performance))
	mc.Debug("Step 3", debug.WithFlag(HTTPRequest))
}

func main() {
	// Define debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: APIV1AuthLogin, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: DatabaseQuery, Name: "db.query", Path: "db.query"},
		{Flag: SecurityCheck, Name: "security.check", Path: "security.check"},
		{Flag: Performance, Name: "performance", Path: "performance"},
		{Flag: HTTPRequest, Name: "http.request", Path: "http.request"},
		{Flag: CacheRedis, Name: "cache.redis", Path: "cache.redis"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)

	// Create service
	service := NewService(dm)

	fmt.Println("=== Flag API Example ===")
	fmt.Println("Demonstrates WithFlag() and WithFlags() APIs.")
	fmt.Println()

	// Test 1: Enable all flags to see all logging
	fmt.Println("--- Test 1: All flags enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query|security.check|performance|http.request|cache.redis")

	service.ProcessRequest()
	fmt.Println()

	// Test 2: Only specific flags to see selective logging
	fmt.Println("--- Test 2: Only security and performance flags ---")
	dm.SetFlags("security.check|performance")

	service.ProcessRequest()
	fmt.Println()

	// Test 3: Only database and HTTP flags
	fmt.Println("--- Test 3: Only database and HTTP flags ---")
	dm.SetFlags("db.query|http.request")

	service.ProcessRequest()
	fmt.Println()

	fmt.Println("=== Flag API Benefits ===")
	fmt.Println("1. WithFlag(flag) - Add single additional flag")
	fmt.Println("2. WithFlags(flag1, flag2, flag3) - Add multiple flags")
	fmt.Println("3. Clean, intuitive API for flag combinations")
	fmt.Println("4. Works with structured logging and severity options")
	fmt.Println("5. Combines with method context flags")
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Println("  mc.Debug(\"message\", debug.WithFlag(SecurityCheck))")
	fmt.Println("  mc.Info(\"message\", debug.WithFlags(DatabaseQuery, Performance))")
	fmt.Println("  mc.Warn(\"message\", debug.WithFlags(Flag1, Flag2), debug.WithAttr(slog.String(\"key\", \"value\")))")
}
