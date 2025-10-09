package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// WithDebugFlag adds a debug flag to the context (immutable, like standard Go context)
func WithDebugFlag(ctx context.Context, flag debug.DebugFlag, description string, dm *debug.DebugManager) context.Context {
	// Get existing flags from context
	existingFlags := debug.GetDebugFlagsFromContext(ctx)
	
	// Combine with new flag
	combinedFlags := existingFlags | flag
	
	// Create new context with combined flags
	newCtx := debug.WithDebugFlags(ctx, combinedFlags)
	
	return newCtx
}

// Mock database service
type DatabaseService struct {
	dm *debug.DebugManager
}

func NewDatabaseService(dm *debug.DebugManager) *DatabaseService {
	return &DatabaseService{dm: dm}
}

func (db *DatabaseService) GetUser(ctx context.Context, userID string) (*User, error) {
	// Log database query - inherits context from parent
	db.dm.Log(ctx, 1<<2, "Querying userID: %s", userID)

	// Simulate database work
	time.Sleep(10 * time.Millisecond)

	// Log query completion
	db.dm.Log(ctx, 1<<2, "User query completed: %s", userID)

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) ValidatePassword(ctx context.Context, userID, password string) bool {
	// Log password validation - inherits context from parent
	db.dm.Log(ctx, 1<<2, "Validating password for user: %s", userID)

	// Simulate password validation
	time.Sleep(5 * time.Millisecond)

	// Log validation result
	db.dm.Log(ctx, 1<<2, "Password validation completed for user: %s", userID)

	return password == "correctpassword"
}

// Mock user model
type User struct {
	ID    string
	Name  string
	Email string
}

// V1 Auth handler with context inheritance
type V1AuthHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewV1AuthHandler(db *DatabaseService, dm *debug.DebugManager) *V1AuthHandler {
	return &V1AuthHandler{
		db: db,
		dm: dm,
	}
}

func (h *V1AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Start with request context
	ctx := r.Context()

	// Add API context - this will be inherited by all child functions
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<3), "api.v1.auth.login", h.dm)

	// Add HTTP request context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<0), "http.request", h.dm)

	// Log login request - now has both api.v1.auth.login and http.request context
	h.dm.Log(ctx, 1<<3, "Login request received")

	// Extract credentials (simplified)
	userID := "123"
	password := "correctpassword"

	// Query user from database - inherits api.v1.auth.login + http.request context
	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		h.dm.Log(ctx, 1<<3, "Login failed: user not found")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Validate password - inherits api.v1.auth.login + http.request context
	if !h.db.ValidatePassword(ctx, userID, password) {
		h.dm.Log(ctx, 1<<3, "Login failed: invalid password")
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Log successful login
	h.dm.Log(ctx, 1<<3, "Login successful for user: %s", user.Email)

	// Write response
	fmt.Fprintf(w, "Login successful: %s", user.Name)
}

func (h *V1AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Start with request context
	ctx := r.Context()

	// Add API context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<4), "api.v1.auth.logout", h.dm)

	// Add HTTP request context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<0), "http.request", h.dm)

	// Log logout request
	h.dm.Log(ctx, 1<<4, "Logout request received")

	// Simulate logout logic
	time.Sleep(5 * time.Millisecond)

	// Log successful logout
	h.dm.Log(ctx, 1<<4, "Logout successful")

	// Write response
	fmt.Fprintf(w, "Logout successful")
}

// V2 API handler with different context
type V2APIHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewV2APIHandler(db *DatabaseService, dm *debug.DebugManager) *V2APIHandler {
	return &V2APIHandler{
		db: db,
		dm: dm,
	}
}

func (h *V2APIHandler) GetUserProfile(w http.ResponseWriter, r *http.Request) {
	// Start with request context
	ctx := r.Context()

	// Add V2 API context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<5), "api.v2.user", h.dm)

	// Add HTTP request context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<0), "http.request", h.dm)

	// Log profile request
	h.dm.Log(ctx, 1<<5, "User profile request received")

	// Extract user ID
	userID := "123"

	// Query user from database - inherits api.v2.user + http.request context
	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		h.dm.Log(ctx, 1<<5, "Profile request failed: user not found")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Log successful profile retrieval
	h.dm.Log(ctx, 1<<5, "User profile retrieved successfully")

	// Write response
	fmt.Fprintf(w, "Profile: %s (%s)", user.Name, user.Email)
}

func main() {
	// Define debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: 1 << 4, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
		{Flag: 1 << 5, Name: "api.v2.user", Path: "api.v2.user"},
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

	fmt.Println("=== Context Inheritance Example ===")
	fmt.Println("This example shows how context flags are inherited")
	fmt.Println("by child functions, following standard Go context patterns.")
	fmt.Println()

	// Test 1: Enable only API v1 auth login - should show DB queries in auth context
	fmt.Println("--- Test 1: Only API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")

	req1, _ := http.NewRequest("POST", "/api/v1/auth/login", nil)
	req1 = req1.WithContext(context.Background())
	w1 := &mockResponseWriter{}
	v1Auth.Login(w1, req1)

	fmt.Println()

	// Test 2: Enable only database queries - should show all DB queries
	fmt.Println("--- Test 2: Only database queries enabled ---")
	dm.SetFlags("db.query")

	req2, _ := http.NewRequest("POST", "/api/v1/auth/login", nil)
	req2 = req2.WithContext(context.Background())
	w2 := &mockResponseWriter{}
	v1Auth.Login(w2, req2)

	fmt.Println()

	// Test 3: Enable API v1 auth login AND database queries - should show both
	fmt.Println("--- Test 3: API v1 auth login AND database queries enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	req3, _ := http.NewRequest("POST", "/api/v1/auth/login", nil)
	req3 = req3.WithContext(context.Background())
	w3 := &mockResponseWriter{}
	v1Auth.Login(w3, req3)

	fmt.Println()

	// Test 4: Enable API v2 user - should show DB queries in V2 context
	fmt.Println("--- Test 4: API v2 user enabled ---")
	dm.SetFlags("api.v2.user")

	req4, _ := http.NewRequest("GET", "/api/v2/user/profile", nil)
	req4 = req4.WithContext(context.Background())
	w4 := &mockResponseWriter{}
	v2API.GetUserProfile(w4, req4)

	fmt.Println()

	// Test 5: Enable HTTP requests - should show all HTTP requests
	fmt.Println("--- Test 5: HTTP requests enabled ---")
	dm.SetFlags("http.request")

	req5, _ := http.NewRequest("POST", "/api/v1/auth/login", nil)
	req5 = req5.WithContext(context.Background())
	w5 := &mockResponseWriter{}
	v1Auth.Login(w5, req5)

	fmt.Println()
	fmt.Println("=== Context Inheritance Benefits ===")
	fmt.Println("1. Context flags are immutable and inherited")
	fmt.Println("2. Child functions inherit parent context")
	fmt.Println("3. Follows standard Go context patterns")
	fmt.Println("4. Selective logging based on context inheritance")
	fmt.Println("5. Easy to enable logging for specific API paths")
	fmt.Println("6. Database queries can be filtered by API context")
}

// Mock response writer for demonstration
type mockResponseWriter struct {
	body []byte
}

func (w *mockResponseWriter) Header() http.Header {
	return make(http.Header)
}

func (w *mockResponseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *mockResponseWriter) WriteHeader(statusCode int) {
	// Mock implementation
}
