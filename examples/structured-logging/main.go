package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Static context flags
const (
	APIV1AuthLogin = debug.DebugFlag(1 << 0) // api.v1.auth.login
	DatabaseQuery  = debug.DebugFlag(1 << 4) // db.query
	SecurityCheck  = debug.DebugFlag(1 << 7) // security.check
	Performance    = debug.DebugFlag(1 << 8) // performance
)

// Mock database service
type DatabaseService struct {
	dm *debug.DebugManager
}

func NewDatabaseService(dm *debug.DebugManager) *DatabaseService {
	return &DatabaseService{dm: dm}
}

func (db *DatabaseService) GetUser(userID string) (*User, error) {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Basic logging
	mc.Debug(fmt.Sprintf("Executing database query for user: %s", userID))
	mc.Info("Connecting to database...")

	// Structured logging with key-value pairs
	mc.Info("Database query executed",
		debug.WithAttr(slog.String("userID", userID)),
		debug.WithAttr(slog.String("query", "SELECT * FROM users WHERE id = ?")),
		debug.WithAttr(slog.Int("rowsAffected", 1)),
		debug.WithAttr(slog.Duration("executionTime", 150*time.Millisecond)))

	// Security event with structured data
	mc.Warn("Sensitive data access",
		debug.WithFlags(SecurityCheck),
		debug.WithAttr(slog.String("userID", userID)),
		debug.WithAttr(slog.String("dataType", "personal_info")),
		debug.WithAttr(slog.String("accessReason", "authentication")))

	// Performance monitoring with structured data
	mc.Info("Query performance metrics",
		debug.WithFlags(Performance),
		debug.WithAttr(slog.String("operation", "user_lookup")),
		debug.WithAttr(slog.Duration("totalTime", 200*time.Millisecond)),
		debug.WithAttr(slog.Int("cacheHits", 0)),
		debug.WithAttr(slog.Int("cacheMisses", 1)))

	mc.Info("Closing database connection")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// V1 Auth handler
type V1AuthHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewV1AuthHandler(db *DatabaseService, dm *debug.DebugManager) *V1AuthHandler {
	return &V1AuthHandler{db: db, dm: dm}
}

func (h *V1AuthHandler) Login(userID, password string) error {
	// Create method context - this persists for the entire method
	mc := h.dm.WithMethodContext(APIV1AuthLogin)

	// Basic logging
	mc.Info(fmt.Sprintf("Login request received for user: %s", userID))

	// Structured logging for request details
	mc.Info("Authentication request",
		debug.WithAttr(slog.String("userID", userID)),
		debug.WithAttr(slog.String("ipAddress", "192.168.1.100")),
		debug.WithAttr(slog.String("userAgent", "Mozilla/5.0...")),
		debug.WithAttr(slog.Time("timestamp", time.Now())))

	// Call database service
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("Login failed: user not found",
			debug.WithAttr(slog.String("userID", userID)),
			debug.WithAttr(slog.String("error", err.Error())))
		return err
	}

	// Security event with detailed context
	mc.Info("Authentication successful",
		debug.WithAttr(slog.String("userID", userID)),
		debug.WithAttr(slog.String("email", user.Email)),
		debug.WithAttr(slog.String("sessionID", "sess_12345")),
		debug.WithAttr(slog.Duration("authTime", 500*time.Millisecond)))

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
		{Flag: SecurityCheck, Name: "security.check", Path: "security.check"},
		{Flag: Performance, Name: "performance", Path: "performance"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)

	// Create services
	db := NewDatabaseService(dm)
	v1Auth := NewV1AuthHandler(db, dm)

	fmt.Println("=== Structured Logging Example ===")
	fmt.Println("Demonstrates structured logging with slog.Attr key-value pairs.")
	fmt.Println("Uses debug.WithAttr() to add structured data to log messages.")
	fmt.Println()

	// Test 1: Enable all flags to see structured logging
	fmt.Println("--- Test 1: All flags enabled - structured logging ---")
	dm.SetFlags("api.v1.auth.login|db.query|security.check|performance")

	v1Auth.Login("123", "password")
	fmt.Println()

	// Test 2: Only database queries to see database structured logging
	fmt.Println("--- Test 2: Only database queries - database structured logging ---")
	dm.SetFlags("db.query")

	db.GetUser("456")
	fmt.Println()

	// Test 3: Only security checks to see security structured logging
	fmt.Println("--- Test 3: Only security checks - security structured logging ---")
	dm.SetFlags("security.check")

	v1Auth.Login("789", "password")
	fmt.Println()

	fmt.Println("=== Structured Logging Benefits ===")
	fmt.Println("1. Rich structured data with key-value pairs")
	fmt.Println("2. Easy to query and analyze in log aggregation systems")
	fmt.Println("3. Consistent with slog.Attr API from Go standard library")
	fmt.Println("4. Perfect for metrics, tracing, and debugging")
	fmt.Println("5. Combines with method context and additional flags")
	fmt.Println("6. JSON output for easy parsing by log processors")
	fmt.Println()
	fmt.Println("Example usage:")
	fmt.Println("  mc.Info(\"User login\", debug.WithAttr(slog.String(\"userID\", \"123\")))")
	fmt.Println("  mc.Warn(\"Security event\", debug.WithAttr(slog.String(\"event\", \"brute_force\")))")
	fmt.Println("  mc.Info(\"Performance\", debug.WithAttr(slog.Duration(\"latency\", 100*time.Millisecond)))")
}
