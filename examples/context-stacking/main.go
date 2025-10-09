package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Static context flags - set at compile time
const (
	APIV1AuthLogin = debug.DebugFlag(1 << 0) // api.v1.auth.login
	DatabaseQuery  = debug.DebugFlag(1 << 2) // db.query
	CacheRedis     = debug.DebugFlag(1 << 3) // cache.redis
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

	// Log the database query
	mc.Debug(fmt.Sprintf("Executing database query: SELECT * FROM users WHERE id = %s", userID))

	// Simulate database work
	time.Sleep(10 * time.Millisecond)

	// Log query completion
	mc.Info(fmt.Sprintf("Database query completed for user: %s", userID))

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(userID, password string) bool {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Log password validation
	mc.Debug(fmt.Sprintf("Validating password for user: %s", userID))

	// Simulate validation work
	time.Sleep(5 * time.Millisecond)

	// Log validation result
	mc.Info(fmt.Sprintf("Password validation completed for user: %s", userID))

	return password == "correctpassword"
}

func (db *DatabaseService) GetUserFromCache(userID string) (*User, error) {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(CacheRedis)

	// Log cache lookup
	mc.Debug(fmt.Sprintf("Looking up user in cache: %s", userID))

	// Simulate cache work
	time.Sleep(2 * time.Millisecond)

	// Log cache result
	mc.Info(fmt.Sprintf("Cache lookup completed for user: %s", userID))

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// Auth handler with method context
type AuthHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewAuthHandler(db *DatabaseService, dm *debug.DebugManager) *AuthHandler {
	return &AuthHandler{db: db, dm: dm}
}

func (h *AuthHandler) Login(userID, password string) error {
	// Create method context - this persists for the entire method
	mc := h.dm.WithMethodContext(APIV1AuthLogin)

	// Log login request
	mc.Info(fmt.Sprintf("Login request received for user: %s", userID))

	// Try cache first
	user, err := h.db.GetUserFromCache(userID)
	if err != nil {
		mc.Warn(fmt.Sprintf("Cache miss for user: %s, falling back to database", userID))
		
		// Fall back to database
		user, err = h.db.GetUser(userID)
		if err != nil {
			mc.Error(fmt.Sprintf("User not found: %s", userID))
			return err
		}
	} else {
		mc.Info(fmt.Sprintf("Cache hit for user: %s", userID))
	}

	// Validate password
	if !h.db.ValidatePassword(userID, password) {
		mc.Error(fmt.Sprintf("Invalid password for user: %s", userID))
		return fmt.Errorf("invalid password")
	}

	// Log successful login
	mc.Info(fmt.Sprintf("Login successful for user: %s", user.Email))

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
		{Flag: CacheRedis, Name: "cache.redis", Path: "cache.redis"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)

	// Create services
	db := NewDatabaseService(dm)
	authHandler := NewAuthHandler(db, dm)

	fmt.Println("=== Context Stacking Example ===")
	fmt.Println("Demonstrates method context stacking.")
	fmt.Println("Each method has its own context that persists for the entire method.")
	fmt.Println("Contexts are isolated - each method manages its own logging context.")
	fmt.Println()

	// Test 1: Enable API v1 auth login - should show auth logs
	fmt.Println("--- Test 1: API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")

	authHandler.Login("123", "correctpassword")
	fmt.Println()

	// Test 2: Enable database queries - should show DB logs
	fmt.Println("--- Test 2: Database queries enabled ---")
	dm.SetFlags("db.query")

	db.GetUser("123")
	db.ValidatePassword("123", "correctpassword")
	fmt.Println()

	// Test 3: Enable cache operations - should show cache logs
	fmt.Println("--- Test 3: Cache operations enabled ---")
	dm.SetFlags("cache.redis")

	db.GetUserFromCache("123")
	fmt.Println()

	// Test 4: Enable all - should show all logs
	fmt.Println("--- Test 4: All flags enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query|cache.redis")

	authHandler.Login("123", "correctpassword")
	fmt.Println()

	fmt.Println("=== Context Stacking Benefits ===")
	fmt.Println("1. Method context flags are set once at the beginning of each method")
	fmt.Println("2. All log calls within the method automatically use the method context")
	fmt.Println("3. No need to pass context or flags to every log call")
	fmt.Println("4. Clean, readable code with consistent logging")
	fmt.Println("5. Easy to understand what each method logs")
	fmt.Println("6. Perfect for service methods, utility functions, etc.")
	fmt.Println()
	fmt.Println("Usage pattern:")
	fmt.Println("  func Method() {")
	fmt.Println("    mc := dm.WithMethodContext(flag)")
	fmt.Println("    mc.Info(\"message\")")
	fmt.Println("    // All logs in this method use the method context")
	fmt.Println("  }")
}
