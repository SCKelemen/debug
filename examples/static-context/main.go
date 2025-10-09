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
	// API context flags
	APIV1AuthLogin  = debug.DebugFlag(1 << 0) // api.v1.auth.login
	APIV1AuthLogout = debug.DebugFlag(1 << 1) // api.v1.auth.logout
	APIV2User       = debug.DebugFlag(1 << 2) // api.v2.user

	// Service context flags
	HTTPRequest   = debug.DebugFlag(1 << 3) // http.request
	DatabaseQuery = debug.DebugFlag(1 << 4) // db.query
	CacheRedis    = debug.DebugFlag(1 << 5) // cache.redis
)

// Mock database service with static context
type DatabaseService struct {
	dm *debug.DebugManager
}

func NewDatabaseService(dm *debug.DebugManager) *DatabaseService {
	return &DatabaseService{dm: dm}
}

func (db *DatabaseService) GetUser(userID string) (*User, error) {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Log database query - will only log if DatabaseQuery is enabled
	mc.Debug(fmt.Sprintf("Executing database query: SELECT * FROM users WHERE id = %s", userID))

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(userID, password string) bool {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Log password validation
	mc.Debug(fmt.Sprintf("Validating password for user: %s", userID))

	return password == "correctpassword"
}

// V1 Auth handler with static context
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

	// Log login request
	mc.Info(fmt.Sprintf("Login request received for user: %s", userID))

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("Login failed: user not found")
		return err
	}

	// Validate password
	if !h.db.ValidatePassword(userID, password) {
		mc.Error("Login failed: invalid password")
		return fmt.Errorf("invalid password")
	}

	// Log successful login
	mc.Info(fmt.Sprintf("Login successful for user: %s", user.Email))

	return nil
}

func (h *V1AuthHandler) Logout(userID string) error {
	// Create method context - this persists for the entire method
	mc := h.dm.WithMethodContext(APIV1AuthLogout)

	// Log logout request
	mc.Info(fmt.Sprintf("Logout request received for user: %s", userID))

	// Log successful logout
	mc.Info(fmt.Sprintf("Logout successful for user: %s", userID))

	return nil
}

// V2 API handler with static context
type V2APIHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewV2APIHandler(db *DatabaseService, dm *debug.DebugManager) *V2APIHandler {
	return &V2APIHandler{db: db, dm: dm}
}

func (h *V2APIHandler) GetUserProfile(userID string) (*User, error) {
	// Create method context - this persists for the entire method
	mc := h.dm.WithMethodContext(APIV2User)

	// Log profile request
	mc.Info(fmt.Sprintf("User profile request received for user: %s", userID))

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("Profile request failed: user not found")
		return nil, err
	}

	// Log successful profile retrieval
	mc.Info(fmt.Sprintf("User profile retrieved successfully for user: %s", user.Email))

	return user, nil
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
		{Flag: APIV1AuthLogout, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
		{Flag: APIV2User, Name: "api.v2.user", Path: "api.v2.user"},
		{Flag: HTTPRequest, Name: "http.request", Path: "http.request"},
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
	v1Auth := NewV1AuthHandler(db, dm)
	v2API := NewV2APIHandler(db, dm)

	fmt.Println("=== Static Context Example ===")
	fmt.Println("Demonstrates static method-scoped context flags.")
	fmt.Println("Each method has its own context that persists for the entire method.")
	fmt.Println()

	// Test 1: Enable API v1 auth login
	fmt.Println("--- Test 1: API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")

	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	// Test 2: Enable API v1 auth logout
	fmt.Println("--- Test 2: API v1 auth logout enabled ---")
	dm.SetFlags("api.v1.auth.logout")

	v1Auth.Logout("123")
	fmt.Println()

	// Test 3: Enable API v2 user
	fmt.Println("--- Test 3: API v2 user enabled ---")
	dm.SetFlags("api.v2.user")

	v2API.GetUserProfile("123")
	fmt.Println()

	// Test 4: Enable database queries
	fmt.Println("--- Test 4: Database queries enabled ---")
	dm.SetFlags("db.query")

	db.GetUser("123")
	db.ValidatePassword("123", "correctpassword")
	fmt.Println()

	// Test 5: Enable multiple flags
	fmt.Println("--- Test 5: Multiple flags enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	fmt.Println("=== Static Context Benefits ===")
	fmt.Println("1. Method context flags are set once at the beginning of each method")
	fmt.Println("2. All log calls within the method automatically use the method context")
	fmt.Println("3. No need to pass context or flags to every log call")
	fmt.Println("4. Clean, readable code with consistent logging")
	fmt.Println("5. Easy to understand what each method logs")
	fmt.Println("6. Perfect for HTTP handlers, service methods, etc.")
}
