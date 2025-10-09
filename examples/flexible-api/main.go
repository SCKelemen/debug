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
	DatabaseQuery  = debug.DebugFlag(1 << 4) // db.query
	CacheRedis     = debug.DebugFlag(1 << 5) // cache.redis
	HTTPRequest    = debug.DebugFlag(1 << 6) // http.request
	SecurityCheck  = debug.DebugFlag(1 << 7) // security.check
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
	
	// Most log calls use only the method context flags
	mc.Debug("Executing database query: SELECT * FROM users WHERE id = %s", userID)
	mc.Info("Connecting to database...")
	mc.Debug("Executing query...")
	mc.Info("Processing results...")
	
	// But for this specific security check, we want to add an additional flag
	// This is an ephemeral, one-line log case that needs different categorization
	mc.Warn(SecurityCheck, "Sensitive data access: user %s", userID)
	
	mc.Info("Closing connection...")
	
	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(userID, password string) bool {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)
	
	// Most log calls use only the method context flags
	mc.Debug("Validating password for user: %s", userID)
	mc.Info("Hashing provided password...")
	mc.Debug("Comparing with stored hash...")
	
	// But for this security event, we want to add an additional flag
	mc.Error(SecurityCheck, "Password validation failed for user: %s", userID)
	
	mc.Info("Password validation completed")
	
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
	
	// Most log calls use only the method context flags
	mc.Info("Login request received for user: %s", userID)
	mc.Debug("Validating user credentials...")
	mc.Info("Checking user permissions...")
	
	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("Login failed: user not found")
		return err
	}
	
	// Validate password - it has its own method context
	if !h.db.ValidatePassword(userID, password) {
		mc.Error("Login failed: invalid password")
		return fmt.Errorf("invalid password")
	}
	
	// For this specific HTTP-related log, we want to add an additional flag
	mc.Info(HTTPRequest, "Creating session for user: %s", userID)
	
	// Most log calls use only the method context flags
	mc.Info("Login successful for user: %s", user.Email)
	
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
	
	// Most log calls use only the method context flags
	mc.Info("User profile request received for user: %s", userID)
	mc.Debug("Validating request...")
	mc.Info("Checking permissions...")
	
	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("Profile request failed: user not found")
		return nil, err
	}
	
	// For this specific cache-related log, we want to add an additional flag
	mc.Debug(CacheRedis, "Checking cache for user profile: %s", userID)
	
	// Most log calls use only the method context flags
	mc.Info("Formatting response...")
	mc.Info("User profile retrieved successfully")
	
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
		{Flag: HTTPRequest, Name: "http.request", Path: "http.request"},
		{Flag: SecurityCheck, Name: "security.check", Path: "security.check"},
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

	fmt.Println("=== Flexible API Example ===")
	fmt.Println("Method context flags are preset, but you can add additional flags for specific cases.")
	fmt.Println()

	// Test 1: Enable only API v1 auth login
	fmt.Println("--- Test 1: Only API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")
	
	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	// Test 2: Enable API v1 auth login AND security checks
	fmt.Println("--- Test 2: API v1 auth login AND security checks enabled ---")
	dm.SetFlags("api.v1.auth.login|security.check")
	
	v1Auth.Login("123", "wrongpassword")
	fmt.Println()

	// Test 3: Enable database queries AND security checks
	fmt.Println("--- Test 3: Database queries AND security checks enabled ---")
	dm.SetFlags("db.query|security.check")
	
	v1Auth.Login("123", "wrongpassword")
	fmt.Println()

	// Test 4: Enable API v2 user AND cache operations
	fmt.Println("--- Test 4: API v2 user AND cache operations enabled ---")
	dm.SetFlags("api.v2.user|cache.redis")
	
	v2API.GetUserProfile("123")
	fmt.Println()

	fmt.Println("=== Flexible API Benefits ===")
	fmt.Println("1. Method context flags are preset for the entire method")
	fmt.Println("2. Add additional flags for ephemeral, one-line log cases")
	fmt.Println("3. Combine method context flags with specific flags as needed")
	fmt.Println("4. Clean API: mc.Debug(\"message\") or mc.Debug(AdditionalFlag, \"message\")")
	fmt.Println("5. Perfect for security events, cache operations, HTTP details, etc.")
	fmt.Println("6. Best of both worlds: convenience + flexibility")
}
