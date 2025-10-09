package main

import (
	"fmt"
	"log/slog"
	"os"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Static context flags - set at compile time
const (
	APIV1AuthLogin = debug.DebugFlag(1 << 0) // api.v1.auth.login
	DatabaseQuery  = debug.DebugFlag(1 << 4) // db.query
)

// WITHOUT method context - you have to specify flags on every line
type DatabaseServiceWithoutContext struct {
	dm *debug.DebugManager
}

func (db *DatabaseServiceWithoutContext) GetUser(userID string) (*User, error) {
	// You have to specify DatabaseQuery on every single log call
	db.dm.Log(DatabaseQuery, "Executing database query: SELECT * FROM users WHERE id = %s", userID)
	db.dm.Log(DatabaseQuery, "Connecting to database...")
	db.dm.Log(DatabaseQuery, "Executing query...")
	db.dm.Log(DatabaseQuery, "Processing results...")
	db.dm.Log(DatabaseQuery, "Closing connection...")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// WITH method context - set once, use everywhere
type DatabaseServiceWithContext struct {
	dm *debug.DebugManager
}

func (db *DatabaseServiceWithContext) GetUser(userID string) (*User, error) {
	// Developer convenience: create method context once instead of passing flags to every log call
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Now we can just use the method context - no need to specify DatabaseQuery on every line
	mc.Debug(fmt.Sprintf("Executing database query: SELECT * FROM users WHERE id = %s", userID))
	mc.Info("Connecting to database...")
	mc.Debug("Executing query...")
	mc.Info("Processing results...")
	mc.Info("Closing connection...")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// Auth handler WITHOUT method context
type AuthHandlerWithoutContext struct {
	db *DatabaseServiceWithoutContext
	dm *debug.DebugManager
}

func (h *AuthHandlerWithoutContext) Login(userID, password string) error {
	// You have to specify APIV1AuthLogin on every single log call
	h.dm.Log(APIV1AuthLogin, "Login request received for user: %s", userID)
	h.dm.Log(APIV1AuthLogin, "Validating credentials...")
	h.dm.Log(APIV1AuthLogin, "Checking permissions...")
	h.dm.Log(APIV1AuthLogin, "Creating session...")
	h.dm.Log(APIV1AuthLogin, "Login successful for user: %s", userID)

	return nil
}

// Auth handler WITH method context
type AuthHandlerWithContext struct {
	db *DatabaseServiceWithContext
	dm *debug.DebugManager
}

func (h *AuthHandlerWithContext) Login(userID, password string) error {
	// Developer convenience: create method context once instead of passing flags to every log call
	mc := h.dm.WithMethodContext(APIV1AuthLogin)

	// Now we can just use the method context - no need to specify APIV1AuthLogin on every line
	mc.Info(fmt.Sprintf("Login request received for user: %s", userID))
	mc.Debug("Validating credentials...")
	mc.Info("Checking permissions...")
	mc.Info("Creating session...")
	mc.Info(fmt.Sprintf("Login successful for user: %s", userID))

	return nil
}

// User model
type User struct {
	ID    string
	Name  string
	Email string
}

func main() {
	// Define debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: APIV1AuthLogin, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: DatabaseQuery, Name: "db.query", Path: "db.query"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)

	// Create services
	dbWithoutContext := &DatabaseServiceWithoutContext{dm: dm}
	dbWithContext := &DatabaseServiceWithContext{dm: dm}
	authWithoutContext := &AuthHandlerWithoutContext{db: dbWithoutContext, dm: dm}
	authWithContext := &AuthHandlerWithContext{db: dbWithContext, dm: dm}

	fmt.Println("=== Developer Convenience Example ===")
	fmt.Println("Comparing logging approaches: without vs with method context.")
	fmt.Println()

	// Test 1: Without method context - verbose and repetitive
	fmt.Println("--- WITHOUT Method Context (Verbose) ---")
	dm.SetFlags("db.query")

	fmt.Println("Database operations:")
	dbWithoutContext.GetUser("123")
	fmt.Println()

	// Test 2: With method context - clean and concise
	fmt.Println("--- WITH Method Context (Clean) ---")
	dm.SetFlags("db.query")

	fmt.Println("Database operations:")
	dbWithContext.GetUser("123")
	fmt.Println()

	// Test 3: Auth without method context - verbose and repetitive
	fmt.Println("--- Auth WITHOUT Method Context (Verbose) ---")
	dm.SetFlags("api.v1.auth.login")

	fmt.Println("Authentication operations:")
	authWithoutContext.Login("123", "password")
	fmt.Println()

	// Test 4: Auth with method context - clean and concise
	fmt.Println("--- Auth WITH Method Context (Clean) ---")
	dm.SetFlags("api.v1.auth.login")

	fmt.Println("Authentication operations:")
	authWithContext.Login("123", "password")
	fmt.Println()

	// Test 5: Both enabled - shows the difference clearly
	fmt.Println("--- Both Flags Enabled (Comparison) ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	fmt.Println("WITHOUT method context:")
	authWithoutContext.Login("123", "password")
	fmt.Println()

	fmt.Println("WITH method context:")
	authWithContext.Login("123", "password")
	fmt.Println()

	fmt.Println("=== Developer Convenience Benefits ===")
	fmt.Println("1. Method context eliminates repetitive flag specification")
	fmt.Println("2. Cleaner, more readable code")
	fmt.Println("3. Less prone to errors (no flag typos)")
	fmt.Println("4. Easier to maintain and refactor")
	fmt.Println("5. Consistent logging within each method")
	fmt.Println("6. Perfect for HTTP handlers, service methods, etc.")
	fmt.Println()
	fmt.Println("Code comparison:")
	fmt.Println("  WITHOUT: db.dm.Log(DatabaseQuery, \"message\")")
	fmt.Println("  WITH:    mc.Info(\"message\")  // mc = dm.WithMethodContext(DatabaseQuery)")
}
