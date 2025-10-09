package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Static context flags - set at compile time
const (
	APIV1AuthLogin = debug.DebugFlag(1 << 0) // api.v1.auth.login
	DatabaseQuery  = debug.DebugFlag(1 << 2) // db.query
	HTTPRequest    = debug.DebugFlag(1 << 3) // http.request
)

// Middleware for adding debug context to HTTP requests
func DebugMiddleware(dm *debug.DebugManager, flag debug.DebugFlag, handlerName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create method context for this middleware
			mc := dm.WithMethodContext(flag)

			// Log middleware entry
			mc.Info(fmt.Sprintf("Middleware entry: %s", handlerName))
			mc.Debug(fmt.Sprintf("Request: %s %s", r.Method, r.URL.Path))
			mc.Debug(fmt.Sprintf("Remote address: %s", r.RemoteAddr))

			// Record start time
			start := time.Now()

			// Call next handler
			next.ServeHTTP(w, r)

			// Log middleware exit
			duration := time.Since(start)
			mc.Info(fmt.Sprintf("Middleware exit: %s (took %v)", handlerName, duration))
		})
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

// HTTP handlers with method context
type AuthHandler struct {
	db *DatabaseService
	dm *debug.DebugManager
}

func NewAuthHandler(db *DatabaseService, dm *debug.DebugManager) *AuthHandler {
	return &AuthHandler{db: db, dm: dm}
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Create method context - this persists for the entire method
	mc := h.dm.WithMethodContext(APIV1AuthLogin)

	// Log HTTP request
	mc.Info(fmt.Sprintf("Login handler called: %s %s", r.Method, r.URL.Path))

	// Extract user credentials from request
	userID := r.URL.Query().Get("user_id")
	password := r.URL.Query().Get("password")

	if userID == "" || password == "" {
		mc.Warn("Missing user credentials in request")
		http.Error(w, "Missing user credentials", http.StatusBadRequest)
		return
	}

	// Log authentication attempt
	mc.Info(fmt.Sprintf("Authentication attempt for user: %s", userID))

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("User not found")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Validate password
	if !h.db.ValidatePassword(userID, password) {
		mc.Error("Invalid password")
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Log successful authentication
	mc.Info(fmt.Sprintf("Authentication successful for user: %s", user.Email))

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "success", "user_id": "%s", "email": "%s"}`, user.ID, user.Email)
}

func (h *AuthHandler) ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Create method context - this persists for the entire method
	mc := h.dm.WithMethodContext(APIV1AuthLogin)

	// Log HTTP request
	mc.Info(fmt.Sprintf("Profile handler called: %s %s", r.Method, r.URL.Path))

	// Extract user ID from request
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		mc.Warn("Missing user_id in request")
		http.Error(w, "Missing user_id", http.StatusBadRequest)
		return
	}

	// Log profile request
	mc.Info(fmt.Sprintf("Profile request for user: %s", userID))

	// Call database service - it has its own method context
	user, err := h.db.GetUser(userID)
	if err != nil {
		mc.Error("User not found")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Log successful profile retrieval
	mc.Info(fmt.Sprintf("Profile retrieved successfully for user: %s", user.Email))

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"user_id": "%s", "name": "%s", "email": "%s"}`, user.ID, user.Name, user.Email)
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
		{Flag: HTTPRequest, Name: "http.request", Path: "http.request"},
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

	fmt.Println("=== Context Middleware Example ===")
	fmt.Println("Demonstrates middleware with method context.")
	fmt.Println("Each middleware and handler has its own context that persists for the entire method.")
	fmt.Println()

	// Test 1: Enable API v1 auth login - should show handler and DB logs
	fmt.Println("--- Test 1: API v1 auth login enabled ---")
	dm.SetFlags("api.v1.auth.login")

	// Simulate HTTP requests
	req1 := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/login"},
		Header: http.Header{"User-Agent": []string{"Mozilla/5.0"}},
	}
	req1.URL.RawQuery = "user_id=123&password=correctpassword"

	authHandler.LoginHandler(&mockResponseWriter{}, req1)
	fmt.Println()

	// Test 2: Enable database queries - should show DB logs only
	fmt.Println("--- Test 2: Database queries enabled ---")
	dm.SetFlags("db.query")

	req2 := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/profile"},
		Header: http.Header{"User-Agent": []string{"Mozilla/5.0"}},
	}
	req2.URL.RawQuery = "user_id=123"

	authHandler.ProfileHandler(&mockResponseWriter{}, req2)
	fmt.Println()

	// Test 3: Enable both - should show all logs
	fmt.Println("--- Test 3: Both API and database enabled ---")
	dm.SetFlags("api.v1.auth.login|db.query")

	req3 := &http.Request{
		Method: "POST",
		URL:    &url.URL{Path: "/login"},
		Header: http.Header{"User-Agent": []string{"Mozilla/5.0"}},
	}
	req3.URL.RawQuery = "user_id=123&password=correctpassword"

	authHandler.LoginHandler(&mockResponseWriter{}, req3)
	fmt.Println()

	fmt.Println("=== Context Middleware Benefits ===")
	fmt.Println("1. Method context flags are set once at the beginning of each middleware/handler")
	fmt.Println("2. All log calls within the middleware/handler automatically use the method context")
	fmt.Println("3. No need to pass context or flags to every log call")
	fmt.Println("4. Clean, readable middleware and handler code")
	fmt.Println("5. Easy to understand what each middleware/handler logs")
	fmt.Println("6. Perfect for HTTP middleware, handlers, etc.")
	fmt.Println()
	fmt.Println("Usage pattern:")
	fmt.Println("  func Middleware(dm *debug.DebugManager, flag debug.DebugFlag) func(http.Handler) http.Handler {")
	fmt.Println("    return func(next http.Handler) http.Handler {")
	fmt.Println("      return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {")
	fmt.Println("        mc := dm.WithMethodContext(flag)")
	fmt.Println("        mc.Info(\"Middleware entry\")")
	fmt.Println("        next.ServeHTTP(w, r)")
	fmt.Println("        mc.Info(\"Middleware exit\")")
	fmt.Println("      })")
	fmt.Println("    }")
	fmt.Println("  }")
}

// Mock response writer for testing
type mockResponseWriter struct {
	statusCode int
	headers    http.Header
	body       []byte
}

func (m *mockResponseWriter) Header() http.Header {
	if m.headers == nil {
		m.headers = make(http.Header)
	}
	return m.headers
}

func (m *mockResponseWriter) Write(data []byte) (int, error) {
	m.body = append(m.body, data...)
	return len(data), nil
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}
