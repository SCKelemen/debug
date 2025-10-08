package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/SCKelemen/debug/debug"
)

func main() {
	// Define some debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: 1 << 4, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
		{Flag: 1 << 5, Name: "api.v2.auth.login", Path: "api.v2.auth.login"},
	}

	// Example 1: V1 Parser with traditional logging
	fmt.Println("=== V1 Parser Example ===")
	v1Parser := debug.NewV1Parser()
	dm1 := debug.NewDebugManager(v1Parser)
	dm1.RegisterFlags(flagDefs)

	// Enable some flags using V1 syntax
	dm1.SetFlags("http.*,db.query")

	// Create context with debug flags
	ctx := debug.WithDebugFlags(context.Background(), debug.DebugFlag(1<<3)) // api.v1.auth.login

	// Log some messages
	dm1.Log(ctx, 1<<0, "Processing HTTP request") // http.request
	dm1.Log(ctx, 1<<2, "Executing database query") // db.query
	dm1.Log(ctx, 1<<1, "This won't be logged - http.response not enabled")

	fmt.Println()

	// Example 2: V2 Parser with slog integration
	fmt.Println("=== V2 Parser Example ===")
	v2Parser := debug.NewV2Parser()
	
	// Create a custom slog handler that writes to stdout
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm2 := debug.NewDebugManagerWithSlogHandler(v2Parser, handler)
	dm2.RegisterFlags(flagDefs)

	// Enable flags using V2 logical expressions
	dm2.SetFlags("http.request|db.query&api.v1.auth.login")

	// Log some messages
	dm2.Log(ctx, 1<<0, "Processing HTTP request with V2")
	dm2.Log(ctx, 1<<2, "Executing database query with V2")
	dm2.Log(ctx, 1<<1, "This won't be logged - http.response not enabled")

	fmt.Println()

	// Example 3: V2 with severity filtering
	fmt.Println("=== V2 with Severity Filtering ===")
	dm3 := debug.NewDebugManager(v2Parser)
	dm3.RegisterFlags(flagDefs)

	// Enable flags with severity filtering
	dm3.SetFlags("http.*:ERROR,db.query:+INFO")

	// Log messages with different severities
	dm3.LogWithSeverity(ctx, 1<<0, debug.SeverityError, "", "HTTP error occurred")
	dm3.LogWithSeverity(ctx, 1<<0, debug.SeverityInfo, "", "HTTP info message (won't be logged)")
	dm3.LogWithSeverity(ctx, 1<<2, debug.SeverityInfo, "", "DB info message")
	dm3.LogWithSeverity(ctx, 1<<2, debug.SeverityWarning, "", "DB warning message")

	fmt.Println()

	// Example 4: Context inheritance
	fmt.Println("=== Context Inheritance Example ===")
	dm4 := debug.NewDebugManager(v1Parser)
	dm4.RegisterFlags(flagDefs)
	dm4.SetFlags("api.*")

	// Create nested context
	apiCtx := debug.WithDebugFlags(context.Background(), 1<<3) // api.v1.auth.login
	authCtx := debug.WithDebugFlags(apiCtx, 1<<2) // db.query

	dm4.Log(apiCtx, 1<<3, "API authentication started")
	dm4.Log(authCtx, 1<<2, "Database query in auth context")
	dm4.Log(context.Background(), 1<<0, "This won't be logged - no context")
}