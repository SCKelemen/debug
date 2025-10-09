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

// Authentication middleware with context marking
func AuthMiddleware(dm *debug.DebugManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add authentication middleware context - inherited by child handlers
		ctx := WithDebugFlag(r.Context(), debug.DebugFlag(1<<3), "auth.middleware", dm)

		// Log authentication attempt
		dm.Log(ctx, 1<<3, "Authentication middleware: processing request for %s", r.URL.Path)

		// Simulate authentication check
		time.Sleep(5 * time.Millisecond)

		// Check for auth token (simplified)
		authToken := r.Header.Get("Authorization")
		if authToken == "" {
			dm.Log(ctx, 1<<3, "Authentication failed: no token provided")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Log successful authentication
		dm.Log(ctx, 1<<3, "Authentication successful for token: %s", authToken[:10]+"...")

		// Pass context to next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logging middleware with context marking
func LoggingMiddleware(dm *debug.DebugManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add HTTP request context - inherited by child handlers
		ctx := WithDebugFlag(r.Context(), debug.DebugFlag(1<<0), "http.request", dm)

		// Log request start
		start := time.Now()
		dm.Log(ctx, 1<<0, "HTTP request started: %s %s", r.Method, r.URL.Path)

		// Create response wrapper to capture status
		wrapper := &responseWrapper{ResponseWriter: w, statusCode: 200}

		// Call next handler
		next.ServeHTTP(wrapper, r.WithContext(ctx))

		// Log request completion
		duration := time.Since(start)
		dm.Log(ctx, 1<<1, "HTTP request completed: %s %s - Status: %d - Duration: %v",
			r.Method, r.URL.Path, wrapper.statusCode, duration)
	})
}

// Cache service with context marking
type CacheService struct {
	dm *debug.DebugManager
}

func NewCacheService(dm *debug.DebugManager) *CacheService {
	return &CacheService{dm: dm}
}

func (c *CacheService) Get(ctx context.Context, key string) (string, bool) {
	// Add cache context - inherits parent context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<4), "cache.redis", c.dm)

	// Log cache lookup
	c.dm.Log(ctx, 1<<4, "Cache lookup: key=%s", key)

	// Simulate cache check
	time.Sleep(2 * time.Millisecond)

	// Mock cache hit
	if key == "user:123" {
		c.dm.Log(ctx, 1<<4, "Cache hit: key=%s, value=user_data", key)
		return "user_data", true
	}

	// Mock cache miss
	c.dm.Log(ctx, 1<<4, "Cache miss: key=%s", key)
	return "", false
}

func (c *CacheService) Set(ctx context.Context, key, value string) error {
	// Add cache context - inherits parent context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<4), "cache.redis", c.dm)

	// Log cache set
	c.dm.Log(ctx, 1<<4, "Cache set: key=%s, value=%s", key, value)

	// Simulate cache write
	time.Sleep(3 * time.Millisecond)

	// Log cache set completion
	c.dm.Log(ctx, 1<<4, "Cache set completed: key=%s", key)

	return nil
}

// Database service with context marking
type DatabaseService struct {
	dm *debug.DebugManager
}

func NewDatabaseService(dm *debug.DebugManager) *DatabaseService {
	return &DatabaseService{dm: dm}
}

func (db *DatabaseService) GetUser(ctx context.Context, userID string) (*User, error) {
	// Add database context - inherits parent context
	ctx = WithDebugFlag(ctx, debug.DebugFlag(1<<2), "db.query", db.dm)

	// Log database query
	db.dm.Log(ctx, 1<<2, "Database query: SELECT * FROM users WHERE id = %s", userID)

	// Simulate database work
	time.Sleep(20 * time.Millisecond)

	// Log query completion
	db.dm.Log(ctx, 1<<2, "Database query completed: user found")

	return &User{ID: userID, Name: "John Doe", Email: "john@example.com"}, nil
}

// User model
type User struct {
	ID    string
	Name  string
	Email string
}

// Main handler with context flow
type UserHandler struct {
	cache *CacheService
	db    *DatabaseService
	dm    *debug.DebugManager
}

func NewUserHandler(cache *CacheService, db *DatabaseService, dm *debug.DebugManager) *UserHandler {
	return &UserHandler{cache: cache, db: db, dm: dm}
}

func (h *UserHandler) GetUserHandler(w http.ResponseWriter, r *http.Request) {
	// Context already has auth and http flags from middleware
	ctx := r.Context()

	// Log handler entry
	h.dm.Log(ctx, 1<<0, "User handler: processing GET request")

	userID := "123"

	// Try cache first - inherits middleware context
	cacheKey := fmt.Sprintf("user:%s", userID)
	if cached, found := h.cache.Get(ctx, cacheKey); found {
		// Log cache hit
		h.dm.Log(ctx, 1<<0, "User handler: returning cached data")
		fmt.Fprintf(w, "Cached User: %s", cached)
		return
	}

	// Cache miss - get from database - inherits middleware context
	user, err := h.db.GetUser(ctx, userID)
	if err != nil {
		h.dm.Log(ctx, 1<<0, "User handler: database error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Cache the result - inherits middleware context
	h.cache.Set(ctx, cacheKey, fmt.Sprintf("%s (%s)", user.Name, user.Email))

	// Log successful response
	h.dm.Log(ctx, 1<<0, "User handler: returning fresh data from database")
	fmt.Fprintf(w, "User: %s (%s)", user.Name, user.Email)
}

// Response wrapper to capture status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
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

	// Enable debug flags - show all components
	dm.SetFlags("http.request|http.response|db.query|auth.middleware|cache.redis")

	fmt.Println("=== Context-Based Middleware Example ===")
	fmt.Println("This example shows how context flows through middleware")
	fmt.Println("and how each component can mark itself in the context.")
	fmt.Println()

	// Create services
	cache := NewCacheService(dm)
	db := NewDatabaseService(dm)
	userHandler := NewUserHandler(cache, db, dm)

	// Create middleware chain
	mux := http.NewServeMux()
	mux.HandleFunc("/users/", userHandler.GetUserHandler)

	// Apply middleware (order matters - outer middleware runs first)
	handlerWithAuth := AuthMiddleware(dm, mux)
	handlerWithLogging := LoggingMiddleware(dm, handlerWithAuth)

	// Simulate HTTP request with authentication
	fmt.Println("--- Simulating HTTP GET /users/123 with auth ---")
	req, _ := http.NewRequest("GET", "/users/123", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req = req.WithContext(context.Background())

	w := &mockResponseWriter{}
	handlerWithLogging.ServeHTTP(w, req)

	fmt.Println()
	fmt.Println("--- Simulating HTTP GET /users/123 without auth ---")
	req2, _ := http.NewRequest("GET", "/users/123", nil)
	req2 = req2.WithContext(context.Background())

	w2 := &mockResponseWriter{}
	handlerWithLogging.ServeHTTP(w2, req2)

	fmt.Println()
	fmt.Println("=== Context Flow Benefits ===")
	fmt.Println("1. Middleware adds context at the entry point")
	fmt.Println("2. Context flows through the entire request lifecycle")
	fmt.Println("3. Each service can add its own debug flags")
	fmt.Println("4. Logs show the complete request flow")
	fmt.Println("5. Easy to trace requests through multiple layers")
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
