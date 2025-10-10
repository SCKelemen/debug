# Debug Logging for Go Microservices - AI Code Generation Guide

This document provides comprehensive examples of how to implement debug logging in Go microservices using the `debug` package. It's designed for AI code generation tools to understand patterns and generate proper logging code from gRPC protobuf specifications.

## Table of Contents
1. [Basic Setup](#basic-setup)
2. [Flag Categories](#flag-categories)
3. [V1 Parser Examples](#v1-parser-examples)
4. [V2 Parser Examples](#v2-parser-examples)
5. [HTTP Handlers](#http-handlers)
6. [Database Operations](#database-operations)
7. [gRPC Services](#grpc-services)
8. [Middleware Patterns](#middleware-patterns)
9. [Complete Microservice Example](#complete-microservice-example)

## Basic Setup

### Package Initialization
```go
package main

import (
    "log/slog"
    "os"
    
    debug "github.com/SCKelemen/debug"
    v1parser "github.com/SCKelemen/debug/v1/parser"
    v2parser "github.com/SCKelemen/debug/v2/parser"
)

// Initialize debug manager with V1 parser (simple comma-separated flags)
func initV1Debug() *debug.DebugManager {
    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    })
    dm := debug.NewDebugManagerWithSlogHandler(v1parser.NewParser(), handler)
    
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
        {Flag: CacheMemcached, Name: "cache.memcached", Path: "cache.memcached"},
        
        // External services
        {Flag: ExternalAPI, Name: "external.api", Path: "external.api"},
        {Flag: ExternalEmail, Name: "external.email", Path: "external.email"},
    })
    
    return dm
}

// Initialize debug manager with V2 parser (logical expressions)
func initV2Debug() *debug.DebugManager {
    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelDebug,
    })
    dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
    
    // Same flag registration as V1
    dm.RegisterFlags([]debug.FlagDefinition{
        {Flag: APIV1UserCreate, Name: "api.v1.user.create", Path: "api.v1.user.create"},
        {Flag: APIV1UserGet, Name: "api.v1.user.get", Path: "api.v1.user.get"},
        {Flag: APIV1UserUpdate, Name: "api.v1.user.update", Path: "api.v1.user.update"},
        {Flag: APIV1UserDelete, Name: "api.v1.user.delete", Path: "api.v1.user.delete"},
        {Flag: DBUserQuery, Name: "db.user.query", Path: "db.user.query"},
        {Flag: DBUserInsert, Name: "db.user.insert", Path: "db.user.insert"},
        {Flag: DBUserUpdate, Name: "db.user.update", Path: "db.user.update"},
        {Flag: DBUserDelete, Name: "db.user.delete", Path: "db.user.delete"},
        {Flag: HTTPRequest, Name: "http.request", Path: "http.request"},
        {Flag: HTTPResponse, Name: "http.response", Path: "http.response"},
        {Flag: CacheRedis, Name: "cache.redis", Path: "cache.redis"},
        {Flag: CacheMemcached, Name: "cache.memcached", Path: "cache.memcached"},
        {Flag: ExternalAPI, Name: "external.api", Path: "external.api"},
        {Flag: ExternalEmail, Name: "external.email", Path: "external.email"},
    })
    
    return dm
}
```

## Flag Categories

### Flag Definitions
```go
// API endpoint flags
const (
    APIV1UserCreate = debug.DebugFlag(1 << 0)  // api.v1.user.create
    APIV1UserGet    = debug.DebugFlag(1 << 1)  // api.v1.user.get
    APIV1UserUpdate = debug.DebugFlag(1 << 2)  // api.v1.user.update
    APIV1UserDelete = debug.DebugFlag(1 << 3)  // api.v1.user.delete
)

// Database operation flags
const (
    DBUserQuery  = debug.DebugFlag(1 << 4)  // db.user.query
    DBUserInsert = debug.DebugFlag(1 << 5)  // db.user.insert
    DBUserUpdate = debug.DebugFlag(1 << 6)  // db.user.update
    DBUserDelete = debug.DebugFlag(1 << 7)  // db.user.delete
)

// HTTP operation flags
const (
    HTTPRequest  = debug.DebugFlag(1 << 8)  // http.request
    HTTPResponse = debug.DebugFlag(1 << 9)  // http.response
)

// Cache operation flags
const (
    CacheRedis     = debug.DebugFlag(1 << 10) // cache.redis
    CacheMemcached = debug.DebugFlag(1 << 11) // cache.memcached
)

// External service flags
const (
    ExternalAPI   = debug.DebugFlag(1 << 12) // external.api
    ExternalEmail = debug.DebugFlag(1 << 13) // external.email
)
```

## V1 Parser Examples

### Simple Flag Combinations
```go
// Enable single flag
dm.SetFlags("api.v1.user.create")

// Enable multiple flags (comma-separated)
dm.SetFlags("api.v1.user.create,api.v1.user.get")

// Enable all user API flags
dm.SetFlags("api.v1.user.create,api.v1.user.get,api.v1.user.update,api.v1.user.delete")

// Enable all database flags
dm.SetFlags("db.user.query,db.user.insert,db.user.update,db.user.delete")

// Enable all flags
dm.SetFlags("api.v1.user.create,api.v1.user.get,api.v1.user.update,api.v1.user.delete,db.user.query,db.user.insert,db.user.update,db.user.delete,http.request,http.response,cache.redis,cache.memcached,external.api,external.email")
```

## V2 Parser Examples

### Logical Expressions
```go
// Enable single flag
dm.SetFlags("api.v1.user.create")

// Enable multiple flags (OR operation)
dm.SetFlags("api.v1.user.create|api.v1.user.get")

// Enable all user API flags
dm.SetFlags("api.v1.user.create|api.v1.user.get|api.v1.user.update|api.v1.user.delete")

// Enable all database flags
dm.SetFlags("db.user.query|db.user.insert|db.user.update|db.user.delete")

// Complex expressions
dm.SetFlags("api.v1.user.*")  // All user API endpoints
dm.SetFlags("db.user.*")      // All user database operations
dm.SetFlags("api.v1.user.create&db.user.insert")  // User creation with DB insert
dm.SetFlags("api.v1.user.*&!db.user.delete")      // All user APIs except delete
dm.SetFlags("(api.v1.user.create|api.v1.user.update)&db.user.*")  // Create/update with all DB ops
```

## HTTP Handlers

### Basic HTTP Handler Pattern
```go
type UserHandler struct {
    db *UserService
    dm *debug.DebugManager
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
    user, err := h.db.CreateUser(req)
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
    
    // Extract user ID from URL
    userID := mux.Vars(r)["id"]
    if userID == "" {
        mc.Warn("Missing user ID in request")
        http.Error(w, "User ID is required", http.StatusBadRequest)
        return
    }
    
    // Call service layer
    user, err := h.db.GetUser(userID)
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
```

## Database Operations

### Database Service Pattern
```go
type UserService struct {
    db *sql.DB
    dm *debug.DebugManager
}

func (s *UserService) CreateUser(req CreateUserRequest) (*User, error) {
    // Create method context - persists for entire method
    mc := s.dm.WithMethodContext(DBUserInsert)
    
    // Log database operation
    mc.Debug("Starting user creation", 
        debug.WithAttr(slog.String("email", req.Email)))
    
    // Prepare SQL statement
    query := `INSERT INTO users (id, email, name, created_at) VALUES ($1, $2, $3, $4)`
    userID := generateID()
    
    // Execute database operation
    _, err := s.db.Exec(query, userID, req.Email, req.Name, time.Now())
    if err != nil {
        mc.Error("Database insert failed", 
            debug.WithAttr(slog.String("error", err.Error())),
            debug.WithAttr(slog.String("query", query)))
        return nil, err
    }
    
    // Log successful operation
    mc.Info("User created in database", 
        debug.WithAttr(slog.String("user_id", userID)),
        debug.WithAttr(slog.String("email", req.Email)))
    
    return &User{
        ID:    userID,
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
    
    // Prepare SQL statement
    query := `SELECT id, email, name, created_at FROM users WHERE id = $1`
    
    // Execute database operation
    row := s.db.QueryRow(query, userID)
    
    var user User
    var createdAt time.Time
    err := row.Scan(&user.ID, &user.Email, &user.Name, &createdAt)
    if err != nil {
        if err == sql.ErrNoRows {
            mc.Warn("User not found", 
                debug.WithAttr(slog.String("user_id", userID)))
            return nil, ErrUserNotFound
        }
        mc.Error("Database query failed", 
            debug.WithAttr(slog.String("error", err.Error())),
            debug.WithAttr(slog.String("query", query)))
        return nil, err
    }
    
    // Log successful operation
    mc.Info("User retrieved from database", 
        debug.WithAttr(slog.String("user_id", user.ID)),
        debug.WithAttr(slog.String("email", user.Email)))
    
    return &user, nil
}

func (s *UserService) UpdateUser(userID string, req UpdateUserRequest) (*User, error) {
    // Create method context - persists for entire method
    mc := s.dm.WithMethodContext(DBUserUpdate)
    
    // Log database operation
    mc.Debug("Starting user update", 
        debug.WithAttr(slog.String("user_id", userID)))
    
    // Prepare SQL statement
    query := `UPDATE users SET email = $1, name = $2, updated_at = $3 WHERE id = $4`
    
    // Execute database operation
    result, err := s.db.Exec(query, req.Email, req.Name, time.Now(), userID)
    if err != nil {
        mc.Error("Database update failed", 
            debug.WithAttr(slog.String("error", err.Error())),
            debug.WithAttr(slog.String("query", query)))
        return nil, err
    }
    
    // Check if user was found
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        mc.Error("Failed to get rows affected", 
            debug.WithAttr(slog.String("error", err.Error())))
        return nil, err
    }
    
    if rowsAffected == 0 {
        mc.Warn("User not found for update", 
            debug.WithAttr(slog.String("user_id", userID)))
        return nil, ErrUserNotFound
    }
    
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
    
    // Prepare SQL statement
    query := `DELETE FROM users WHERE id = $1`
    
    // Execute database operation
    result, err := s.db.Exec(query, userID)
    if err != nil {
        mc.Error("Database delete failed", 
            debug.WithAttr(slog.String("error", err.Error())),
            debug.WithAttr(slog.String("query", query)))
        return err
    }
    
    // Check if user was found
    rowsAffected, err := result.RowsAffected()
    if err != nil {
        mc.Error("Failed to get rows affected", 
            debug.WithAttr(slog.String("error", err.Error())))
        return err
    }
    
    if rowsAffected == 0 {
        mc.Warn("User not found for deletion", 
            debug.WithAttr(slog.String("user_id", userID)))
        return ErrUserNotFound
    }
    
    // Log successful operation
    mc.Info("User deleted from database", 
        debug.WithAttr(slog.String("user_id", userID)))
    
    return nil
}
```

## gRPC Services

### gRPC Service Pattern
```go
type UserGRPCService struct {
    db *UserService
    dm *debug.DebugManager
}

func (s *UserGRPCService) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
    // Create method context - persists for entire method
    mc := s.dm.WithMethodContext(APIV1UserCreate)
    
    // Log gRPC request
    mc.Info("gRPC request received", 
        debug.WithAttr(slog.String("method", "CreateUser")),
        debug.WithAttr(slog.String("email", req.Email)))
    
    // Validate request
    if req.Email == "" {
        mc.Warn("Missing email in gRPC request")
        return nil, status.Error(codes.InvalidArgument, "Email is required")
    }
    
    // Convert to internal request
    internalReq := CreateUserRequest{
        Email: req.Email,
        Name:  req.Name,
    }
    
    // Call service layer
    user, err := s.db.CreateUser(internalReq)
    if err != nil {
        mc.Error("Failed to create user", 
            debug.WithAttr(slog.String("error", err.Error())))
        return nil, status.Error(codes.Internal, "Failed to create user")
    }
    
    // Log successful response
    mc.Info("User created successfully", 
        debug.WithAttr(slog.String("user_id", user.ID)),
        debug.WithAttr(slog.String("email", user.Email)))
    
    // Convert to gRPC response
    return &pb.CreateUserResponse{
        User: &pb.User{
            Id:    user.ID,
            Email: user.Email,
            Name:  user.Name,
        },
    }, nil
}

func (s *UserGRPCService) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
    // Create method context - persists for entire method
    mc := s.dm.WithMethodContext(APIV1UserGet)
    
    // Log gRPC request
    mc.Info("gRPC request received", 
        debug.WithAttr(slog.String("method", "GetUser")),
        debug.WithAttr(slog.String("user_id", req.Id)))
    
    // Validate request
    if req.Id == "" {
        mc.Warn("Missing user ID in gRPC request")
        return nil, status.Error(codes.InvalidArgument, "User ID is required")
    }
    
    // Call service layer
    user, err := s.db.GetUser(req.Id)
    if err != nil {
        if err == ErrUserNotFound {
            mc.Warn("User not found", 
                debug.WithAttr(slog.String("user_id", req.Id)))
            return nil, status.Error(codes.NotFound, "User not found")
        }
        mc.Error("Failed to get user", 
            debug.WithAttr(slog.String("error", err.Error())))
        return nil, status.Error(codes.Internal, "Failed to get user")
    }
    
    // Log successful response
    mc.Info("User retrieved successfully", 
        debug.WithAttr(slog.String("user_id", user.ID)),
        debug.WithAttr(slog.String("email", user.Email)))
    
    // Convert to gRPC response
    return &pb.GetUserResponse{
        User: &pb.User{
            Id:    user.ID,
            Email: user.Email,
            Name:  user.Name,
        },
    }, nil
}
```

## Middleware Patterns

### HTTP Middleware
```go
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
                debug.WithAttr(slog.String("remote_addr", r.RemoteAddr)),
                debug.WithAttr(slog.String("user_agent", r.UserAgent())))
            
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
```

### gRPC Interceptor
```go
func LoggingInterceptor(dm *debug.DebugManager) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        // Create method context for this interceptor
        mc := dm.WithMethodContext(HTTPRequest)
        
        // Log gRPC request start
        start := time.Now()
        mc.Info("gRPC request started", 
            debug.WithAttr(slog.String("method", info.FullMethod)))
        
        // Call next handler
        resp, err := handler(ctx, req)
        
        // Log gRPC request completion
        duration := time.Since(start)
        if err != nil {
            mc.Error("gRPC request failed", 
                debug.WithAttr(slog.String("method", info.FullMethod)),
                debug.WithAttr(slog.String("error", err.Error())),
                debug.WithAttr(slog.Duration("duration", duration)))
        } else {
            mc.Info("gRPC request completed", 
                debug.WithAttr(slog.String("method", info.FullMethod)),
                debug.WithAttr(slog.Duration("duration", duration)))
        }
        
        return resp, err
    }
}
```

## Complete Microservice Example

### Main Application
```go
package main

import (
    "context"
    "database/sql"
    "log"
    "net/http"
    "os"
    
    "github.com/gorilla/mux"
    "google.golang.org/grpc"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
    
    debug "github.com/SCKelemen/debug"
    v2parser "github.com/SCKelemen/debug/v2/parser"
)

func main() {
    // Initialize debug manager
    dm := initDebug()
    
    // Set debug flags based on environment
    if os.Getenv("DEBUG_FLAGS") != "" {
        dm.SetFlags(os.Getenv("DEBUG_FLAGS"))
    } else {
        // Default: enable all user API and database operations
        dm.SetFlags("api.v1.user.*|db.user.*")
    }
    
    // Initialize database
    db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    if err != nil {
        log.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()
    
    // Initialize services
    userService := NewUserService(db, dm)
    userHandler := NewUserHandler(userService, dm)
    userGRPCService := NewUserGRPCService(userService, dm)
    
    // Setup HTTP routes
    router := mux.NewRouter()
    router.Use(LoggingMiddleware(dm))
    
    router.HandleFunc("/api/v1/users", userHandler.CreateUser).Methods("POST")
    router.HandleFunc("/api/v1/users/{id}", userHandler.GetUser).Methods("GET")
    router.HandleFunc("/api/v1/users/{id}", userHandler.UpdateUser).Methods("PUT")
    router.HandleFunc("/api/v1/users/{id}", userHandler.DeleteUser).Methods("DELETE")
    
    // Setup gRPC server
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(LoggingInterceptor(dm)),
    )
    pb.RegisterUserServiceServer(grpcServer, userGRPCService)
    
    // Start servers
    go func() {
        log.Println("Starting HTTP server on :8080")
        log.Fatal(http.ListenAndServe(":8080", router))
    }()
    
    log.Println("Starting gRPC server on :9090")
    log.Fatal(grpcServer.Serve(listener))
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
        {Flag: CacheMemcached, Name: "cache.memcached", Path: "cache.memcached"},
        
        // External services
        {Flag: ExternalAPI, Name: "external.api", Path: "external.api"},
        {Flag: ExternalEmail, Name: "external.email", Path: "external.email"},
    })
    
    return dm
}
```

## Environment Configuration

### Docker Compose Example
```yaml
version: '3.8'
services:
  user-service:
    build: .
    environment:
      - DEBUG_FLAGS=api.v1.user.*|db.user.*|http.request
      - DATABASE_URL=postgres://user:pass@db:5432/users
    ports:
      - "8080:8080"
      - "9090:9090"
    depends_on:
      - db
      - redis

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=users
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:6-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

### Kubernetes ConfigMap Example
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: user-service-config
data:
  DEBUG_FLAGS: "api.v1.user.*|db.user.*|http.request"
  LOG_LEVEL: "debug"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        envFrom:
        - configMapRef:
            name: user-service-config
        ports:
        - containerPort: 8080
        - containerPort: 9090
```

## Code Generation Patterns

### For AI Code Generators

When generating microservices from gRPC protobuf specifications, follow these patterns:

1. **For each gRPC service method:**
   - Create a corresponding API flag: `APIV1{ServiceName}{MethodName}`
   - Create a method context with the flag
   - Log request start with method name and key parameters
   - Log response completion with success/error status

2. **For each database operation:**
   - Create corresponding DB flags: `DB{EntityName}{Operation}`
   - Create a method context with the flag
   - Log SQL operations with query and parameters
   - Log success/failure with affected rows

3. **For HTTP handlers:**
   - Use HTTP request/response flags
   - Log request details (method, path, headers)
   - Log response details (status code, duration)

4. **For external service calls:**
   - Create external service flags: `External{ServiceName}`
   - Log request/response details
   - Log errors and retries

5. **Always use structured logging:**
   - Use `debug.WithAttr()` for key-value pairs
   - Include request IDs, user IDs, and other identifiers
   - Use appropriate log levels (Debug, Info, Warn, Error)

This pattern ensures consistent, debuggable microservices that can be easily monitored and troubleshot in production environments.
