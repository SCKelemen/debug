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

// FunctionContext represents a function's debug context
type FunctionContext struct {
	mc   *debug.MethodContext
	name string
}

// WithFunctionContext creates a new method context with function marking
func WithFunctionContext(dm *debug.DebugManager, flag debug.DebugFlag, functionName string) *FunctionContext {
	// Create method context
	mc := dm.WithMethodContext(flag)

	// Log function entry
	mc.Info(fmt.Sprintf("Function entry: %s", functionName))

	return &FunctionContext{
		mc:   mc,
		name: functionName,
	}
}

// Cleanup logs function exit and can be used with defer
func (fc *FunctionContext) Cleanup() {
	fc.mc.Info(fmt.Sprintf("Function exit: %s", fc.name))
}

// Log logs a message using the function context
func (fc *FunctionContext) Log(level string, message string, args ...interface{}) {
	switch level {
	case "debug":
		fc.mc.Debug(fmt.Sprintf(message, args...))
	case "info":
		fc.mc.Info(fmt.Sprintf(message, args...))
	case "warn":
		fc.mc.Warn(fmt.Sprintf(message, args...))
	case "error":
		fc.mc.Error(fmt.Sprintf(message, args...))
	default:
		fc.mc.Info(fmt.Sprintf(message, args...))
	}
}

// Mock database service
type DatabaseService struct {
	dm *debug.DebugManager
}

func NewDatabaseService(dm *debug.DebugManager) *DatabaseService {
	return &DatabaseService{dm: dm}
}

func (db *DatabaseService) GetUser(userID string) (*User, error) {
	// Create function context - this persists for the entire function
	fc := WithFunctionContext(db.dm, DatabaseQuery, "GetUser")
	defer fc.Cleanup()

	// Log the database query
	fc.Log("debug", "Executing database query: SELECT * FROM users WHERE id = %s", userID)

	// Simulate database work
	time.Sleep(10 * time.Millisecond)

	// Log query completion
	fc.Log("info", "Database query completed for user: %s", userID)

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(userID, password string) bool {
	// Create function context - this persists for the entire function
	fc := WithFunctionContext(db.dm, DatabaseQuery, "ValidatePassword")
	defer fc.Cleanup()

	// Log password validation
	fc.Log("debug", "Validating password for user: %s", userID)

	// Simulate validation work
	time.Sleep(5 * time.Millisecond)

	// Log validation result
	fc.Log("info", "Password validation completed for user: %s", userID)

	return password == "correctpassword"
}

func (db *DatabaseService) GetUserFromCache(userID string) (*User, error) {
	// Create function context - this persists for the entire function
	fc := WithFunctionContext(db.dm, CacheRedis, "GetUserFromCache")
	defer fc.Cleanup()

	// Log cache lookup
	fc.Log("debug", "Looking up user in cache: %s", userID)

	// Simulate cache work
	time.Sleep(2 * time.Millisecond)

	// Log cache result
	fc.Log("info", "Cache lookup completed for user: %s", userID)

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// Auth handler with function context
type AuthHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewAuthHandler(db *DatabaseService, dm *debug.DebugManager) *AuthHandler {
	return &AuthHandler{db: db, dm: dm}
}

func (h *AuthHandler) Login(userID, password string) error {
	// Create function context - this persists for the entire function
	fc := WithFunctionContext(h.dm, APIV1AuthLogin, "Login")
	defer fc.Cleanup()

	// Log login request
	fc.Log("info", "Login request received for user: %s", userID)

	// Try cache first
	user, err := h.db.GetUserFromCache(userID)
	if err != nil {
		fc.Log("warn", "Cache miss for user: %s, falling back to database", userID)
		
		// Fall back to database
		user, err = h.db.GetUser(userID)
		if err != nil {
			fc.Log("error", "User not found: %s", userID)
			return err
		}
	} else {
		fc.Log("info", "Cache hit for user: %s", userID)
	}

	// Validate password
	if !h.db.ValidatePassword(userID, password) {
		fc.Log("error", "Invalid password for user: %s", userID)
		return fmt.Errorf("invalid password")
	}

	// Log successful login
	fc.Log("info", "Login successful for user: %s", user.Email)

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

	fmt.Println("=== Context Functions Example ===")
	fmt.Println("Demonstrates function context with automatic entry/exit logging.")
	fmt.Println("Each function has its own context that persists for the entire function.")
	fmt.Println("Uses defer for automatic cleanup and exit logging.")
	fmt.Println()

	// Test 1: Enable API v1 auth login - should show function entry/exit
	fmt.Println("--- Test 1: API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")

	authHandler.Login("123", "correctpassword")
	fmt.Println()

	// Test 2: Enable database queries - should show DB function entry/exit
	fmt.Println("--- Test 2: Database queries enabled ---")
	dm.SetFlags("db.query")

	db.GetUser("123")
	db.ValidatePassword("123", "correctpassword")
	fmt.Println()

	// Test 3: Enable cache operations - should show cache function entry/exit
	fmt.Println("--- Test 3: Cache operations enabled ---")
	dm.SetFlags("cache.redis")

	db.GetUserFromCache("123")
	fmt.Println()

	// Test 4: Enable all - should show all function entry/exit
	fmt.Println("--- Test 4: All flags enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query|cache.redis")

	authHandler.Login("123", "correctpassword")
	fmt.Println()

	fmt.Println("=== Context Functions Benefits ===")
	fmt.Println("1. Function context flags are set once at the beginning of each function")
	fmt.Println("2. All log calls within the function automatically use the function context")
	fmt.Println("3. Automatic function entry/exit logging with defer")
	fmt.Println("4. Clean, readable code with consistent logging")
	fmt.Println("5. Easy to understand what each function logs")
	fmt.Println("6. Perfect for service methods, utility functions, etc.")
	fmt.Println()
	fmt.Println("Usage pattern:")
	fmt.Println("  fc := WithFunctionContext(dm, flag, \"FunctionName\")")
	fmt.Println("  defer fc.Cleanup()")
	fmt.Println("  fc.Log(\"info\", \"message\")")
}
