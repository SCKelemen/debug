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
	// Add database query context - inherits parent context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<2), "db.query", db.dm)

	// Log the database query
	db.dm.Log(ctx, 1<<2, "Executing database query: SELECT * FROM users WHERE id = %s", userID)

	// Simulate database work
	time.Sleep(10 * time.Millisecond)

	// Log query completion
	db.dm.Log(ctx, 1<<2, "Database query completed for user: %s", userID)

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

func (db *DatabaseService) UpdateUser(ctx context.Context, user *User) error {
	// Add database query context - inherits parent context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<2), "db.query", db.dm)

	// Log the database update
	db.dm.Log(ctx, 1<<2, "Executing database update: UPDATE users SET name = %s WHERE id = %s", user.Name, user.ID)

	// Simulate database work
	time.Sleep(15 * time.Millisecond)

	// Log update completion
	db.dm.Log(ctx, 1<<2, "Database update completed for user: %s", user.ID)

	return nil
}

// Mock user model
type User struct {
	ID    string
	Name  string
	Email string
}

// HTTP handler with context marking
type UserHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewUserHandler(db *DatabaseService, dm *debug.DebugManager) *UserHandler {
	return &UserHandler{db: db, dm: dm}
}

func (h *UserHandler) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	// Start with request context
	ctx := r.Context()

	// Add HTTP request context - inherited by child functions
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<0), "http.request", h.dm)

	// Log the incoming HTTP request
	h.dm.Log(ctx, 1<<0, "Processing HTTP GET request to /users/%s", r.URL.Path)

	// Extract user ID from URL (simplified)
	userID := "123"

	// Call database service (context is inherited)
	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		// Log error with HTTP context
		h.dm.Log(ctx, 1<<0, "Database error in HTTP handler: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log successful response
	h.dm.Log(ctx, 1<<1, "HTTP response: user retrieved successfully")

	// Write response
	fmt.Fprintf(w, "User: %s (%s)", user.Name, user.Email)
}

func (h *UserHandler) UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Start with request context
	ctx := r.Context()

	// Add HTTP request context - inherited by child functions
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<0), "http.request", h.dm)

	// Log the incoming HTTP request
	h.dm.Log(ctx, 1<<0, "Processing HTTP PUT request to /users/%s", r.URL.Path)

	// Extract user ID from URL (simplified)
	userID := "123"

	// Create updated user (simplified)
	user := &User{ID: userID, Name: "Jane Doe", Email: "jane@example.com"}

	// Call database service (context is inherited)
	err := h.db.UpdateUser(ctx, user)
	if err != nil {
		// Log error with HTTP context
		h.dm.Log(ctx, 1<<0, "Database error in HTTP handler: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Log successful response
	h.dm.Log(ctx, 1<<1, "HTTP response: user updated successfully")

	// Write response
	fmt.Fprintf(w, "User updated: %s (%s)", user.Name, user.Email)
}

func main() {
	// Define debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "auth.middleware", Path: "auth.middleware"},
		{Flag: 1 << 4, Name: "cache.redis", Path: "cache.redis"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)

	// Enable debug flags - show HTTP requests and database queries
	dm.SetFlags("http.request|db.query")

	fmt.Println("=== Context-Based Logging Example ===")
	fmt.Println("This example shows how to use context to mark log functions")
	fmt.Println("in HTTP handlers and database calls.")
	fmt.Println()

	// Create services
	db := NewDatabaseService(dm)
	userHandler := NewUserHandler(db, dm)

	// Simulate HTTP requests
	fmt.Println("--- Simulating HTTP GET /users/123 ---")
	req1, _ := http.NewRequest("GET", "/users/123", nil)
	req1 = req1.WithContext(context.Background())

	// Create a mock response writer
	w1 := &mockResponseWriter{}
	userHandler.GetUserHandler(w1, req1)

	fmt.Println()
	fmt.Println("--- Simulating HTTP PUT /users/123 ---")
	req2, _ := http.NewRequest("PUT", "/users/123", nil)
	req2 = req2.WithContext(context.Background())

	w2 := &mockResponseWriter{}
	userHandler.UpdateUserHandler(w2, req2)

	fmt.Println()
	fmt.Println("=== Context Marking Benefits ===")
	fmt.Println("1. Context is set at function entry points")
	fmt.Println("2. Context flows through the call stack")
	fmt.Println("3. Each function can add its own debug flags")
	fmt.Println("4. Logs are automatically tagged with the right context")
	fmt.Println("5. Easy to enable/disable logging for specific components")
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
