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
	APIV1AuthLogin = debug.DebugFlag(1 << 0) // api.v1.auth.login
	APIV2User      = debug.DebugFlag(1 << 2) // api.v2.user

	// Service context flags
	DatabaseQuery = debug.DebugFlag(1 << 4) // db.query
	CacheRedis    = debug.DebugFlag(1 << 5) // cache.redis
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

	// Now all log calls in this method automatically use DatabaseQuery - no need to specify it!
	mc.Log("Executing database query: SELECT * FROM users WHERE id = %s", userID)
	mc.Log("Connecting to database...")
	mc.Log("Executing query...")
	mc.Log("Processing results...")
	mc.Log("Closing connection...")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(userID, password string) bool {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// All log calls automatically use DatabaseQuery - no need to specify it!
	mc.Log("Validating password for user: %s", userID)
	mc.Log("Hashing provided password...")
	mc.Log("Comparing with stored hash...")
	mc.Log("Password validation completed")

	return password == "correctpassword"
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

	// All log calls in this method automatically use APIV1AuthLogin - no need to specify it!
	mc.Log("Login request received for user: %s", userID)
	mc.Log("Validating user credentials...")
	mc.Log("Checking user permissions...")

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Log("Login failed: user not found")
		return err
	}

	// Validate password - it has its own method context
	if !h.db.ValidatePassword(userID, password) {
		mc.Log("Login failed: invalid password")
		return fmt.Errorf("invalid password")
	}

	// More logging in the auth context
	mc.Log("Creating session...")
	mc.Log("Login successful for user: %s", user.Email)

	return nil
}

// V2 API handler
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

	// All log calls in this method automatically use APIV2User - no need to specify it!
	mc.Log("User profile request received for user: %s", userID)
	mc.Log("Validating request...")
	mc.Log("Checking permissions...")

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Log("Profile request failed: user not found")
		return nil, err
	}

	// More logging in the API context
	mc.Log("Formatting response...")
	mc.Log("User profile retrieved successfully")

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
		{Flag: APIV2User, Name: "api.v2.user", Path: "api.v2.user"},
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

	fmt.Println("=== Method Context Example ===")
	fmt.Println("Method context persists for the entire method execution.")
	fmt.Println("Set context once at the top of the method, then all log calls inherit it.")
	fmt.Println()

	// Test 1: Enable only API v1 auth login
	fmt.Println("--- Test 1: Only API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")

	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	// Test 2: Enable only database queries
	fmt.Println("--- Test 2: Only database queries enabled ---")
	dm.SetFlags("db.query")

	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	// Test 3: Enable both API v1 auth login AND database queries
	fmt.Println("--- Test 3: API v1 auth login AND database queries enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	// Test 4: Enable API v2 user
	fmt.Println("--- Test 4: API v2 user enabled ---")
	dm.SetFlags("api.v2.user")

	v2API.GetUserProfile("123")
	fmt.Println()

	fmt.Println("=== Method Context Benefits ===")
	fmt.Println("1. Method context persists for the entire method execution")
	fmt.Println("2. Set context once at the top of the method")
	fmt.Println("3. All log calls in the method inherit the context")
	fmt.Println("4. No need to pass context around or specify flags repeatedly")
	fmt.Println("5. Clean, maintainable code with static method-scoped markers")
	fmt.Println("6. Each method has its own context - no dynamic passing around")
}
