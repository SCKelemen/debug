package main

import (
	"fmt"
	"log/slog"
	"os"

	debug "github.com/SCKelemen/debug"
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

	fmt.Println("=== V2 Parser Example (Logical Expressions) ===")

	// Create V2 debug manager with traditional logging
	dm := debug.NewDebugManager(v2parser.NewParser())
	dm.RegisterFlags(flagDefs)

	// Enable flags using V2 logical expressions
	dm.SetFlags("http.request|db.query")

	// Create method contexts for different operations
	mc1 := dm.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc1.Info("Processing HTTP request with V2")

	mc2 := dm.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc2.Info("Executing database query with V2")

	mc3 := dm.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc3.Info("This won't be logged - http.response not enabled")

	fmt.Println()

	// Example with complex logical expressions
	fmt.Println("=== V2 Complex Logical Expressions ===")
	dm2 := debug.NewDebugManager(v2parser.NewParser())
	dm2.RegisterFlags(flagDefs)
	dm2.SetFlags("(http.request|http.response)&api.v1.*")

	// Create method contexts for different operations
	mc4 := dm2.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc4.Info("HTTP request in API context")               // Should log

	mc5 := dm2.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc5.Info("HTTP response in API context")              // Should log

	mc6 := dm2.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc6.Info("DB query in API context")                   // Won't log (not http.*)

	fmt.Println()

	// Example with V1 compatibility
	fmt.Println("=== V2 with V1 Compatibility ===")
	dm3 := debug.NewDebugManager(v2parser.NewParser())
	dm3.RegisterFlags(flagDefs)

	// V1 syntax still works in V2
	dm3.SetFlags("http.request,db.query")

	// Create method contexts for different operations
	mc7 := dm3.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc7.Info("HTTP request with V1 syntax in V2")

	mc8 := dm3.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc8.Info("DB query with V1 syntax in V2")

	fmt.Println()

	// Example with slog integration
	fmt.Println("=== V2 Parser with Slog ===")

	// Create custom slog handler
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm4 := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm4.RegisterFlags(flagDefs)
	dm4.SetFlags("api.v1.*|api.v2.*")

	// Create method contexts for different operations
	mc9 := dm4.WithMethodContext(debug.DebugFlag(1 << 3)) // api.v1.auth.login
	mc9.Info("API v1 authentication with slog")

	mc10 := dm4.WithMethodContext(debug.DebugFlag(1 << 5)) // api.v2.auth.login
	mc10.Info("API v2 authentication with slog")
}
