package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Flag definitions for microservice
const (
	// API endpoint flags
	APIV1UserCreate = debug.DebugFlag(1 << 0) // api.v1.user.create
	APIV1UserGet    = debug.DebugFlag(1 << 1) // api.v1.user.get
	APIV1UserUpdate = debug.DebugFlag(1 << 2) // api.v1.user.update
	APIV1UserDelete = debug.DebugFlag(1 << 3) // api.v1.user.delete

	// Database operation flags
	DBUserQuery  = debug.DebugFlag(1 << 4) // db.user.query
	DBUserInsert = debug.DebugFlag(1 << 5) // db.user.insert
	DBUserUpdate = debug.DebugFlag(1 << 6) // db.user.update
	DBUserDelete = debug.DebugFlag(1 << 7) // db.user.delete

	// HTTP operation flags
	HTTPRequest  = debug.DebugFlag(1 << 8) // http.request
	HTTPResponse = debug.DebugFlag(1 << 9) // http.response

	// Cache operation flags
	CacheRedis = debug.DebugFlag(1 << 10) // cache.redis
)

// User model
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Request/Response models
type CreateUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type UpdateUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Mock database service
type UserService struct {
	dm *debug.DebugManager
}

func NewUserService(dm *debug.DebugManager) *UserService {
	return &UserService{dm: dm}
}

func (s *UserService) CreateUser(req CreateUserRequest) (*User, error) {
	// Create method context - persists for entire method
	mc := s.dm.WithMethodContext(DBUserInsert)

	// Log database operation
	mc.Debug("Starting user creation",
		debug.WithAttr(slog.String("email", req.Email)))

	// Simulate database work
	time.Sleep(10 * time.Millisecond)

	// Log successful operation
	mc.Info("User created in database",
		debug.WithAttr(slog.String("user_id", "123")),
		debug.WithAttr(slog.String("email", req.Email)))

	return &User{
		ID:    "123",
		Email: req.Email,
		Name:  req.Name,
	}, nil
}

func (s *UserService) GetUser(userID string) (*User, error) {
	// Create method context - persists for entire method
	mc := s.dm.WithMethodContext(DBUserQuery)

	// Log database operation
	mc.Debug("Starting user query",
		debug.WithAttr(slog.String("user_id", userID)))

	// Simulate database work
	time.Sleep(5 * time.Millisecond)

	// Log successful operation
	mc.Info("User retrieved from database",
		debug.WithAttr(slog.String("user_id", userID)),
		debug.WithAttr(slog.String("email", "user@example.com")))

	return &User{
		ID:    userID,
		Email: "user@example.com",
		Name:  "John Doe",
	}, nil
}

func (s *UserService) UpdateUser(userID string, req UpdateUserRequest) (*User, error) {
	// Create method context - persists for entire method
	mc := s.dm.WithMethodContext(DBUserUpdate)

	// Log database operation
	mc.Debug("Starting user update",
		debug.WithAttr(slog.String("user_id", userID)))

	// Simulate database work
	time.Sleep(8 * time.Millisecond)

	// Log successful operation
	mc.Info("User updated in database",
		debug.WithAttr(slog.String("user_id", userID)),
		debug.WithAttr(slog.String("email", req.Email)))

	return &User{
		ID:    userID,
		Email: req.Email,
		Name:  req.Name,
	}, nil
}

func (s *UserService) DeleteUser(userID string) error {
	// Create method context - persists for entire method
	mc := s.dm.WithMethodContext(DBUserDelete)

	// Log database operation
	mc.Debug("Starting user deletion",
		debug.WithAttr(slog.String("user_id", userID)))

	// Simulate database work
	time.Sleep(5 * time.Millisecond)

	// Log successful operation
	mc.Info("User deleted from database",
		debug.WithAttr(slog.String("user_id", userID)))

	return nil
}

// HTTP handler
type UserHandler struct {
	userService *UserService
	dm          *debug.DebugManager
}

func NewUserHandler(userService *UserService, dm *debug.DebugManager) *UserHandler {
	return &UserHandler{userService: userService, dm: dm}
}

func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	// Create method context - persists for entire method
	mc := h.dm.WithMethodContext(APIV1UserCreate)

	// Log HTTP request
	mc.Info("HTTP request received",
		debug.WithAttr(slog.String("method", r.Method)),
		debug.WithAttr(slog.String("path", r.URL.Path)),
		debug.WithAttr(slog.String("remote_addr", r.RemoteAddr)))

	// Parse request body
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		mc.Error("Failed to parse request body",
			debug.WithAttr(slog.String("error", err.Error())))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Email == "" {
		mc.Warn("Missing email in request")
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	// Call service layer
	user, err := h.userService.CreateUser(req)
	if err != nil {
		mc.Error("Failed to create user",
			debug.WithAttr(slog.String("error", err.Error())))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Log successful response
	mc.Info("User created successfully",
		debug.WithAttr(slog.String("user_id", user.ID)),
		debug.WithAttr(slog.String("email", user.Email)))

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	// Create method context - persists for entire method
	mc := h.dm.WithMethodContext(APIV1UserGet)

	// Log HTTP request
	mc.Info("HTTP request received",
		debug.WithAttr(slog.String("method", r.Method)),
		debug.WithAttr(slog.String("path", r.URL.Path)))

	// Extract user ID from URL (simplified)
	userID := "123" // In real app, extract from URL path

	// Call service layer
	user, err := h.userService.GetUser(userID)
	if err != nil {
		mc.Error("Failed to get user",
			debug.WithAttr(slog.String("user_id", userID)),
			debug.WithAttr(slog.String("error", err.Error())))
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Log successful response
	mc.Info("User retrieved successfully",
		debug.WithAttr(slog.String("user_id", user.ID)),
		debug.WithAttr(slog.String("email", user.Email)))

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// HTTP middleware
func LoggingMiddleware(dm *debug.DebugManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create method context for this middleware
			mc := dm.WithMethodContext(HTTPRequest)

			// Log request start
			start := time.Now()
			mc.Info("HTTP request started",
				debug.WithAttr(slog.String("method", r.Method)),
				debug.WithAttr(slog.String("path", r.URL.Path)),
				debug.WithAttr(slog.String("remote_addr", r.RemoteAddr)))

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Call next handler
			next.ServeHTTP(wrapped, r)

			// Log request completion
			duration := time.Since(start)
			mc.Info("HTTP request completed",
				debug.WithAttr(slog.Int("status_code", wrapped.statusCode)),
				debug.WithAttr(slog.Duration("duration", duration)))
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func main() {
	// Initialize debug manager
	dm := initDebug()

	// Set debug flags based on environment or default
	debugFlags := os.Getenv("DEBUG_FLAGS")
	if debugFlags == "" {
		// Default: enable all user API and database operations
		debugFlags = "api.v1.user.*|db.user.*|http.request"
	}
	dm.SetFlags(debugFlags)

	// Initialize services
	userService := NewUserService(dm)
	userHandler := NewUserHandler(userService, dm)

	// Setup HTTP routes
	http.HandleFunc("/api/v1/users", userHandler.CreateUser)
	http.HandleFunc("/api/v1/users/123", userHandler.GetUser)

	// Add middleware (commented out for demo)
	// handler := LoggingMiddleware(dm)(http.DefaultServeMux)

	fmt.Println("=== Microservice Debug Logging Example ===")
	fmt.Println("Demonstrates debug logging in a Go microservice.")
	fmt.Println("Shows HTTP handlers, database operations, and middleware.")
	fmt.Println()

	// Test different flag combinations
	fmt.Println("--- Test 1: All user API and database operations ---")
	dm.SetFlags("api.v1.user.*|db.user.*|http.request")

	// Simulate HTTP requests
	req1, _ := http.NewRequest("POST", "/api/v1/users", nil)
	req1.Body = &mockBody{data: `{"email":"test@example.com","name":"Test User"}`}
	userHandler.CreateUser(&mockResponseWriter{}, req1)
	fmt.Println()

	fmt.Println("--- Test 2: Only database operations ---")
	dm.SetFlags("db.user.*")

	userService.GetUser("123")
	fmt.Println()

	fmt.Println("--- Test 3: Only HTTP requests ---")
	dm.SetFlags("http.request")

	req2, _ := http.NewRequest("GET", "/api/v1/users/123", nil)
	userHandler.GetUser(&mockResponseWriter{}, req2)
	fmt.Println()

	fmt.Println("=== Microservice Debug Logging Benefits ===")
	fmt.Println("1. Method context flags are set once at the beginning of each method")
	fmt.Println("2. All log calls within the method automatically use the method context")
	fmt.Println("3. No need to pass context or flags to every log call")
	fmt.Println("4. Clean, readable microservice code")
	fmt.Println("5. Easy to understand what each method logs")
	fmt.Println("6. Perfect for HTTP handlers, database operations, middleware, etc.")
	fmt.Println("7. Structured logging with key-value pairs for easy parsing")
	fmt.Println("8. Environment-based flag configuration for different environments")
}

func initDebug() *debug.DebugManager {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)

	// Register all service flags
	dm.RegisterFlags([]debug.FlagDefinition{
		// API endpoints
		{Flag: APIV1UserCreate, Name: "api.v1.user.create", Path: "api.v1.user.create"},
		{Flag: APIV1UserGet, Name: "api.v1.user.get", Path: "api.v1.user.get"},
		{Flag: APIV1UserUpdate, Name: "api.v1.user.update", Path: "api.v1.user.update"},
		{Flag: APIV1UserDelete, Name: "api.v1.user.delete", Path: "api.v1.user.delete"},

		// Database operations
		{Flag: DBUserQuery, Name: "db.user.query", Path: "db.user.query"},
		{Flag: DBUserInsert, Name: "db.user.insert", Path: "db.user.insert"},
		{Flag: DBUserUpdate, Name: "db.user.update", Path: "db.user.update"},
		{Flag: DBUserDelete, Name: "db.user.delete", Path: "db.user.delete"},

		// HTTP operations
		{Flag: HTTPRequest, Name: "http.request", Path: "http.request"},
		{Flag: HTTPResponse, Name: "http.response", Path: "http.response"},

		// Cache operations
		{Flag: CacheRedis, Name: "cache.redis", Path: "cache.redis"},
	})

	return dm
}

// Mock types for testing
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

type mockBody struct {
	data string
	pos  int
}

func (m *mockBody) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, fmt.Errorf("EOF")
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockBody) Close() error {
	return nil
}
