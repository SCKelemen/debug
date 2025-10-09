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
	HTTPRequest   = debug.DebugFlag(1 << 6) // http.request
	SecurityCheck = debug.DebugFlag(1 << 7) // security.check
	Performance   = debug.DebugFlag(1 << 8) // performance
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
	mc.Debug(fmt.Sprintf("Executing database query: SELECT * FROM users WHERE id = %s", userID))
	mc.Info("Connecting to database...")
	mc.Debug("Executing query...")
	mc.Info("Processing results...")

	// But for this specific security check, we want to add an additional flag
	// Using the options pattern - clean and idiomatic Go
	mc.Warn(fmt.Sprintf("Sensitive data access: user %s", userID), debug.WithFlag(SecurityCheck))

	// Performance monitoring with additional flag
	mc.Info("Query execution time: 150ms", debug.WithFlag(Performance))

	mc.Info("Closing connection...")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(userID, password string) bool {
	// Create method context - this persists for the entire method
	mc := db.dm.WithMethodContext(DatabaseQuery)

	// Most log calls use only the method context flags
	mc.Debug(fmt.Sprintf("Validating password for user: %s", userID))
	mc.Info("Hashing provided password...")
	mc.Debug("Comparing with stored hash...")

	// Security event with additional flag and custom severity
	mc.Error(fmt.Sprintf("Password validation failed for user: %s", userID),
		debug.WithFlag(SecurityCheck),
		debug.WithSeverity(debug.SeverityError))

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
	mc.Info(fmt.Sprintf("Login request received for user: %s", userID))
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

	// HTTP-related log with additional flag
	mc.Info(fmt.Sprintf("Creating session for user: %s", userID), debug.WithFlag(HTTPRequest))

	// Performance monitoring
	mc.Info("Login processing time: 200ms", debug.WithFlag(Performance))

	// Most log calls use only the method context flags
	mc.Info(fmt.Sprintf("Login successful for user: %s", user.Email))

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
	mc.Info(fmt.Sprintf("User profile request received for user: %s", userID))
	mc.Debug("Validating request...")
	mc.Info("Checking permissions...")

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("Profile request failed: user not found")
		return nil, err
	}

	// Cache operation with additional flag
	mc.Debug(fmt.Sprintf("Checking cache for user profile: %s", userID), debug.WithFlag(CacheRedis))

	// Performance monitoring
	mc.Info("Cache hit rate: 85%", debug.WithFlag(Performance))

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
	v2API := NewV2APIHandler(db, dm)

	fmt.Println("=== Options API Example ===")
	fmt.Println("Method context flags are preset, but you can add options for specific cases.")
	fmt.Println("Uses the idiomatic Go options pattern: debug.WithFlags(), debug.WithSeverity()")
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

	// Test 3: Enable database queries AND performance monitoring
	fmt.Println("--- Test 3: Database queries AND performance monitoring enabled ---")
	dm.SetFlags("db.query|performance")

	v1Auth.Login("123", "correctpassword")
	fmt.Println()

	// Test 4: Enable API v2 user AND cache operations
	fmt.Println("--- Test 4: API v2 user AND cache operations enabled ---")
	dm.SetFlags("api.v2.user|cache.redis")

	v2API.GetUserProfile("123")
	fmt.Println()

	fmt.Println("=== Options API Benefits ===")
	fmt.Println("1. Method context flags are preset for the entire method")
	fmt.Println("2. Add options for ephemeral, one-line log cases")
	fmt.Println("3. Idiomatic Go options pattern: debug.WithFlags(), debug.WithSeverity()")
	fmt.Println("4. Clean API: mc.Debug(\"message\") or mc.Debug(\"message\", debug.WithFlag(flag))")
	fmt.Println("5. Multiple options: mc.Debug(\"message\", debug.WithFlag(flag), debug.WithSeverity(severity))")
	fmt.Println("6. Perfect for security events, cache operations, performance monitoring, etc.")
	fmt.Println("7. Best of both worlds: convenience + flexibility + idiomatic Go")
}
