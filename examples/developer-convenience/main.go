package main

import (
	"context"
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

// WITHOUT context - you have to specify flags on every line
type DatabaseServiceWithoutContext struct {
	dm *debug.DebugManager
}

func (db *DatabaseServiceWithoutContext) GetUser(ctx context.Context, userID string) (*User, error) {
	// You have to specify DatabaseQuery on every single log call
	db.dm.Log(ctx, DatabaseQuery, "Executing database query: SELECT * FROM users WHERE id = %s", userID)
	db.dm.Log(ctx, DatabaseQuery, "Connecting to database...")
	db.dm.Log(ctx, DatabaseQuery, "Executing query...")
	db.dm.Log(ctx, DatabaseQuery, "Processing results...")
	db.dm.Log(ctx, DatabaseQuery, "Closing connection...")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// WITH context - set once, use everywhere
type DatabaseServiceWithContext struct {
	dm *debug.DebugManager
}

func (db *DatabaseServiceWithContext) GetUser(ctx context.Context, userID string) (*User, error) {
	// Developer convenience: set context once instead of passing flags to every log call
	ctx = debug.WithDebugFlags(ctx, DatabaseQuery)

	// Now we can just use the context - no need to specify DatabaseQuery on every line
	db.dm.Log(ctx, DatabaseQuery, "Executing database query: SELECT * FROM users WHERE id = %s", userID)
	db.dm.Log(ctx, DatabaseQuery, "Connecting to database...")
	db.dm.Log(ctx, DatabaseQuery, "Executing query...")
	db.dm.Log(ctx, DatabaseQuery, "Processing results...")
	db.dm.Log(ctx, DatabaseQuery, "Closing connection...")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// Auth handler without context
type AuthHandlerWithoutContext struct {
	db *DatabaseServiceWithoutContext
	dm *debug.DebugManager
}

func (h *AuthHandlerWithoutContext) Login(ctx context.Context, userID, password string) error {
	// You have to specify APIV1AuthLogin on every single log call
	h.dm.Log(ctx, APIV1AuthLogin, "Login request received for user: %s", userID)
	h.dm.Log(ctx, APIV1AuthLogin, "Validating user credentials...")
	h.dm.Log(ctx, APIV1AuthLogin, "Checking user permissions...")
	h.dm.Log(ctx, APIV1AuthLogin, "Creating session...")
	h.dm.Log(ctx, APIV1AuthLogin, "Login successful for user: %s", userID)

	// Call database service
	_, err := h.db.GetUser(ctx, userID)
	return err
}

// Auth handler with context
type AuthHandlerWithContext struct {
	db *DatabaseServiceWithContext
	dm *debug.DebugManager
}

func (h *AuthHandlerWithContext) Login(ctx context.Context, userID, password string) error {
	// Developer convenience: set context once instead of passing flags to every log call
	ctx = debug.WithDebugFlags(ctx, APIV1AuthLogin)

	// Now we can just use the context - no need to specify APIV1AuthLogin on every line
	h.dm.Log(ctx, APIV1AuthLogin, "Login request received for user: %s", userID)
	h.dm.Log(ctx, APIV1AuthLogin, "Validating user credentials...")
	h.dm.Log(ctx, APIV1AuthLogin, "Checking user permissions...")
	h.dm.Log(ctx, APIV1AuthLogin, "Creating session...")
	h.dm.Log(ctx, APIV1AuthLogin, "Login successful for user: %s", userID)

	// Call database service
	_, err := h.db.GetUser(ctx, userID)
	return err
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

	fmt.Println("=== Developer Convenience: Context vs No Context ===")
	fmt.Println("Context flags are just developer convenience to avoid writing flags on every line.")
	fmt.Println()

	ctx := context.Background()

	// Test 1: Without context - you have to specify flags on every line
	fmt.Println("--- Test 1: WITHOUT context (verbose, repetitive) ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	authWithoutContext.Login(ctx, "123", "password")
	fmt.Println()

	// Test 2: With context - set once, use everywhere
	fmt.Println("--- Test 2: WITH context (clean, maintainable) ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	authWithContext.Login(ctx, "123", "password")
	fmt.Println()

	fmt.Println("=== Code Comparison ===")
	fmt.Println("WITHOUT context:")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Login request received\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Validating credentials\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Checking permissions\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Creating session\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Login successful\")")
	fmt.Println()
	fmt.Println("WITH context:")
	fmt.Println("  ctx = debug.WithDebugFlags(ctx, APIV1AuthLogin)")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Login request received\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Validating credentials\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Checking permissions\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Creating session\")")
	fmt.Println("  h.dm.Log(ctx, APIV1AuthLogin, \"Login successful\")")
	fmt.Println()
	fmt.Println("=== Benefits ===")
	fmt.Println("1. Set context once instead of passing flags to every log call")
	fmt.Println("2. Cleaner, more maintainable code")
	fmt.Println("3. Context flags are just compile-time markers")
	fmt.Println("4. Simple and predictable behavior")
	fmt.Println("5. Easy to enable/disable logging for specific sections")
}
