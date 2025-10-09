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

func (db *DatabaseService) GetUser(ctx context.Context, userID string) (*User, error) {
	// Static context: this function always belongs to database query section
	ctx = debug.WithDebugFlags(ctx, DatabaseQuery)

	// Log database query - will only log if DatabaseQuery OR context flags are enabled
	db.dm.Log(ctx, DatabaseQuery, "Executing database query: SELECT * FROM users WHERE id = %s", userID)

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(ctx context.Context, userID, password string) bool {
	// Static context: this function always belongs to database query section
	ctx = debug.WithDebugFlags(ctx, DatabaseQuery)

	// Log password validation
	db.dm.Log(ctx, DatabaseQuery, "Validating password for user: %s", userID)

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

func (h *V1AuthHandler) Login(ctx context.Context, userID, password string) error {
	// Static context: this function always belongs to API v1 auth login section
	ctx = debug.WithDebugFlags(ctx, APIV1AuthLogin)

	// Log login request
	h.dm.Log(ctx, APIV1AuthLogin, "Login request received for user: %s", userID)

	// Call database service - inherits API v1 auth login context
	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	// Validate password - inherits API v1 auth login context
	if !h.db.ValidatePassword(ctx, userID, password) {
		h.dm.Log(ctx, APIV1AuthLogin, "Login failed: invalid password")
		return fmt.Errorf("invalid password")
	}

	// Log successful login
	h.dm.Log(ctx, APIV1AuthLogin, "Login successful for user: %s", user.Email)

	return nil
}

func (h *V1AuthHandler) Logout(ctx context.Context, userID string) error {
	// Static context: this function always belongs to API v1 auth logout section
	ctx = debug.WithDebugFlags(ctx, APIV1AuthLogout)

	// Log logout request
	h.dm.Log(ctx, APIV1AuthLogout, "Logout request received for user: %s", userID)

	// Log successful logout
	h.dm.Log(ctx, APIV1AuthLogout, "Logout successful for user: %s", userID)

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

func (h *V2APIHandler) GetUserProfile(ctx context.Context, userID string) (*User, error) {
	// Static context: this function always belongs to API v2 user section
	ctx = debug.WithDebugFlags(ctx, APIV2User)

	// Log profile request
	h.dm.Log(ctx, APIV2User, "User profile request received for user: %s", userID)

	// Call database service - inherits API v2 user context
	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		h.dm.Log(ctx, APIV2User, "Profile request failed: user not found")
		return nil, err
	}

	// Log successful profile retrieval
	h.dm.Log(ctx, APIV2User, "User profile retrieved successfully")

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

	fmt.Println("=== Intersection Patterns Example ===")
	fmt.Println("Context flags provide additional filtering criteria for log calls.")
	fmt.Println()

	ctx := context.Background()

	// Test 1: Log all database queries
	fmt.Println("--- Test 1: Log all database queries (debug_flags=db.query) ---")
	dm.SetFlags("db.query")

	v1Auth.Login(ctx, "123", "correctpassword")
	fmt.Println()
	v2API.GetUserProfile(ctx, "123")
	fmt.Println()

	// Test 2: Log database queries only in auth APIs
	fmt.Println("--- Test 2: Log database queries only in auth APIs (debug_flags=db.query&api.v1.auth.*) ---")
	dm.SetFlags("db.query&api.v1.auth.*")

	v1Auth.Login(ctx, "123", "correctpassword")
	fmt.Println()
	v2API.GetUserProfile(ctx, "123")
	fmt.Println()

	// Test 3: Log auth logins but ignore database queries
	fmt.Println("--- Test 3: Log auth logins but ignore database queries (debug_flags=api.v1.auth.login&!db.query) ---")
	dm.SetFlags("api.v1.auth.login&!db.query")

	v1Auth.Login(ctx, "123", "correctpassword")
	fmt.Println()
	v2API.GetUserProfile(ctx, "123")
	fmt.Println()

	// Test 4: Log all API calls but ignore database queries
	fmt.Println("--- Test 4: Log all API calls but ignore database queries (debug_flags=api.*&!db.query) ---")
	dm.SetFlags("api.*&!db.query")

	v1Auth.Login(ctx, "123", "correctpassword")
	fmt.Println()
	v1Auth.Logout(ctx, "123")
	fmt.Println()
	v2API.GetUserProfile(ctx, "123")
	fmt.Println()

	// Test 5: Log database queries in any API context
	fmt.Println("--- Test 5: Log database queries in any API context (debug_flags=db.query&api.*) ---")
	dm.SetFlags("db.query&api.*")

	v1Auth.Login(ctx, "123", "correctpassword")
	fmt.Println()
	v2API.GetUserProfile(ctx, "123")
	fmt.Println()

	fmt.Println("=== Intersection Pattern Benefits ===")
	fmt.Println("1. Context flags provide additional filtering criteria")
	fmt.Println("2. Support for complex patterns like 'db.query&api.v1.auth.*'")
	fmt.Println("3. Can exclude specific flags with '!db.query'")
	fmt.Println("4. Database queries can be filtered by API context")
	fmt.Println("5. Fine-grained control over what gets logged")
}
