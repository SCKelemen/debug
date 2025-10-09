package main

import (
	"fmt"
	"log/slog"
	"os"

	debug "github.com/SCKelemen/debug"
	v1parser "github.com/SCKelemen/debug/v1/parser"
	v2parser "github.com/SCKelemen/debug/v2/parser"
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
	dm1 := debug.NewDebugManager(v1parser.NewParser())
	dm1.RegisterFlags(flagDefs)
	dm1.SetFlags("http.*,db.query")

	// Create method context for HTTP requests
	mc1 := dm1.WithMethodContext(debug.DebugFlag(1 << 0))
	mc1.Info("Processing HTTP request")

	// Create method context for database queries
	mc2 := dm1.WithMethodContext(debug.DebugFlag(1 << 2))
	mc2.Info("Executing database query")

	fmt.Println()

	// Example 2: V2 Parser with logical expressions
	fmt.Println("=== V2 Parser Example ===")
	dm2 := debug.NewDebugManager(v2parser.NewParser())
	dm2.RegisterFlags(flagDefs)
	dm2.SetFlags("http.request|db.query")

	// Create method context for HTTP requests
	mc3 := dm2.WithMethodContext(debug.DebugFlag(1 << 0))
	mc3.Info("Processing HTTP request with V2")

	// Create method context for database queries
	mc4 := dm2.WithMethodContext(debug.DebugFlag(1 << 2))
	mc4.Info("Executing database query with V2")

	fmt.Println()

	// Example 3: V2 Parser with slog integration
	fmt.Println("=== V2 Parser with Slog ===")
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm3 := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm3.RegisterFlags(flagDefs)
	dm3.SetFlags("api.v1.*|api.v2.*")

	// Create method context for API v1 authentication
	mc5 := dm3.WithMethodContext(debug.DebugFlag(1 << 3))
	mc5.Info("API v1 authentication")

	// Create method context for API v2 authentication
	mc6 := dm3.WithMethodContext(debug.DebugFlag(1 << 5))
	mc6.Info("API v2 authentication")

	fmt.Println()

	// Example 4: V2 with complex logical expressions
	fmt.Println("=== V2 Complex Logical Expressions ===")
	dm4 := debug.NewDebugManager(v2parser.NewParser())
	dm4.RegisterFlags(flagDefs)
	dm4.SetFlags("(http.request|http.response)&api.v1.*")

	// Create method context for HTTP request in API context
	mc7 := dm4.WithMethodContext(debug.DebugFlag(1 << 0))
	mc7.Info("HTTP request in API context")

	// Create method context for HTTP response in API context
	mc8 := dm4.WithMethodContext(debug.DebugFlag(1 << 1))
	mc8.Info("HTTP response in API context")

	// Create method context for DB query (won't log due to complex expression)
	mc9 := dm4.WithMethodContext(debug.DebugFlag(1 << 2))
	mc9.Info("DB query in API context (won't log)")

	fmt.Println()

	// Example 5: V2 with V1 compatibility
	fmt.Println("=== V2 with V1 Compatibility ===")
	dm5 := debug.NewDebugManager(v2parser.NewParser())
	dm5.RegisterFlags(flagDefs)
	dm5.SetFlags("http.request,db.query") // V1 syntax in V2 parser

	// Create method context for HTTP request with V1 syntax in V2
	mc10 := dm5.WithMethodContext(debug.DebugFlag(1 << 0))
	mc10.Info("HTTP request with V1 syntax in V2")

	// Create method context for DB query with V1 syntax in V2
	mc11 := dm5.WithMethodContext(debug.DebugFlag(1 << 2))
	mc11.Info("DB query with V1 syntax in V2")
}
