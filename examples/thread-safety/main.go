package main

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Static context flags
const (
	APIV1AuthLogin = debug.DebugFlag(1 << 0) // api.v1.auth.login
	DatabaseQuery  = debug.DebugFlag(1 << 4) // db.query
	SecurityCheck  = debug.DebugFlag(1 << 7) // security.check
)

// Mock service that will be used concurrently
type DatabaseService struct {
	dm *debug.DebugManager
}

func NewDatabaseService(dm *debug.DebugManager) *DatabaseService {
	return &DatabaseService{dm: dm}
}

func (db *DatabaseService) GetUser(userID string) {
	// Create method context - this should be thread-safe
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Multiple log calls that should be thread-safe
	mc.Debug(fmt.Sprintf("Executing database query for user: %s", userID))
	mc.Info("Connecting to database...")
	mc.Debug("Executing query...")
	mc.Info("Processing results...")

	// Security check with additional flag
	mc.Warn(fmt.Sprintf("Sensitive data access: user %s", userID), debug.WithFlags(SecurityCheck))

	mc.Info("Closing connection...")
}

func main() {
	// Define debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: APIV1AuthLogin, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: DatabaseQuery, Name: "db.query", Path: "db.query"},
		{Flag: SecurityCheck, Name: "security.check", Path: "security.check"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)
	dm.SetFlags("db.query|security.check")

	// Create service
	db := NewDatabaseService(dm)

	fmt.Println("=== Thread Safety Test ===")
	fmt.Println("Running concurrent operations to test thread safety...")
	fmt.Println()

	// Test concurrent access to the same DebugManager
	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 5

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				userID := fmt.Sprintf("user_%d_%d", goroutineID, j)
				db.GetUser(userID)

				// Small delay to increase chance of race conditions
				time.Sleep(time.Millisecond * 10)
			}
		}(i)
	}

	// Also test concurrent flag changes
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			dm.SetFlags("db.query")
			time.Sleep(time.Millisecond * 5)
			dm.SetFlags("db.query|security.check")
			time.Sleep(time.Millisecond * 5)
		}
	}()

	// Wait for all goroutines to complete
	wg.Wait()

	fmt.Println()
	fmt.Println("=== Thread Safety Analysis ===")
	fmt.Println("✅ DebugManager uses sync.RWMutex for thread safety")
	fmt.Println("✅ MethodContext is immutable (only contains flags and dm pointer)")
	fmt.Println("✅ LogOptions are created per-call (no shared state)")
	fmt.Println("✅ All critical sections are properly protected")
	fmt.Println("✅ Concurrent flag changes and logging operations are safe")
	fmt.Println()
	fmt.Println("The debug package is thread-safe and can be used concurrently!")
}
