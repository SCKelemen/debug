package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/SCKelemen/debug/debug"
	v2 "github.com/SCKelemen/debug/v2"
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

	fmt.Println("=== V2 Parser Example (Logical Expressions) ===")

	// Create V2 debug manager with traditional logging
	dm := v2.NewDebugManager()
	dm.RegisterFlags(flagDefs)

	// Enable flags using V2 logical expressions
	dm.SetFlags("http.request|db.query")

	// Create context with debug flags
	ctx := debug.WithDebugFlags(context.Background(), debug.DebugFlag(1<<3)) // api.v1.auth.login

	// Log some messages
	dm.Log(ctx, 1<<0, "Processing HTTP request with V2")  // http.request
	dm.Log(ctx, 1<<2, "Executing database query with V2") // db.query
	dm.Log(ctx, 1<<1, "This won't be logged - http.response not enabled")

	fmt.Println()

	// Example with complex logical expressions
	fmt.Println("=== V2 Complex Logical Expressions ===")
	dm2 := v2.NewDebugManager()
	dm2.RegisterFlags(flagDefs)
	dm2.SetFlags("(http.request|http.response)&api.v1.*")

	dm2.Log(ctx, 1<<0, "HTTP request in API context")  // Should log
	dm2.Log(ctx, 1<<1, "HTTP response in API context") // Should log
	dm2.Log(ctx, 1<<2, "DB query in API context")      // Won't log (not http.*)

	fmt.Println()

	// Example with V1 compatibility
	fmt.Println("=== V2 with V1 Compatibility ===")
	dm3 := v2.NewDebugManager()
	dm3.RegisterFlags(flagDefs)

	// V1 syntax still works in V2
	dm3.SetFlags("http.request,db.query")

	dm3.Log(ctx, 1<<0, "HTTP request with V1 syntax in V2")
	dm3.Log(ctx, 1<<2, "DB query with V1 syntax in V2")

	fmt.Println()

	// Example with slog integration
	fmt.Println("=== V2 Parser with Slog ===")

	// Create custom slog handler
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm4 := v2.NewDebugManagerWithSlogHandler(handler)
	dm4.RegisterFlags(flagDefs)
	dm4.SetFlags("api.v1.*|api.v2.*")

	dm4.Log(ctx, 1<<3, "API v1 authentication")
	dm4.Log(ctx, 1<<5, "API v2 authentication")
}
