package main

import (
	"fmt"

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

	fmt.Println("=== V1 vs V2 Parser Comparison ===")

	// V1 Parser - Simple comma-separated
	fmt.Println("\n--- V1 Parser (Simple) ---")
	dm1 := debug.NewDebugManager(v1parser.NewParser())
	dm1.RegisterFlags(flagDefs)
	dm1.SetFlags("http.*,db.query")

	// Create method contexts for different operations
	mc1 := dm1.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc1.Info("HTTP request with V1")

	mc2 := dm1.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc2.Info("HTTP response with V1")

	mc3 := dm1.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc3.Info("DB query with V1")

	// V2 Parser - Logical expressions
	fmt.Println("\n--- V2 Parser (Logical Expressions) ---")
	dm2 := debug.NewDebugManager(v2parser.NewParser())
	dm2.RegisterFlags(flagDefs)
	dm2.SetFlags("http.request|db.query") // Same result as V1

	// Create method contexts for different operations
	mc4 := dm2.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc4.Info("HTTP request with V2")

	mc5 := dm2.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc5.Info("HTTP response with V2")                     // Won't log (not in expression)

	mc6 := dm2.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc6.Info("DB query with V2")

	// V2 Parser - Complex logical expressions
	fmt.Println("\n--- V2 Parser (Complex Logic) ---")
	dm3 := debug.NewDebugManager(v2parser.NewParser())
	dm3.RegisterFlags(flagDefs)
	dm3.SetFlags("(http.request|http.response)&api.v1.*")

	// Create method contexts for different operations
	mc7 := dm3.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc7.Info("HTTP request in API context")               // Will log

	mc8 := dm3.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc8.Info("HTTP response in API context")              // Will log

	mc9 := dm3.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc9.Info("DB query in API context")                   // Won't log (not http.*)

	// V2 Parser - V1 compatibility
	fmt.Println("\n--- V2 Parser (V1 Compatibility) ---")
	dm4 := debug.NewDebugManager(v2parser.NewParser())
	dm4.RegisterFlags(flagDefs)
	dm4.SetFlags("http.request,db.query") // V1 syntax in V2 parser

	// Create method contexts for different operations
	mc10 := dm4.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc10.Info("HTTP request with V1 syntax in V2")

	mc11 := dm4.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc11.Info("DB query with V1 syntax in V2")

	fmt.Println("\n=== Summary ===")
	fmt.Println("V1 Parser: Simple comma-separated flags (http.*,db.query)")
	fmt.Println("V2 Parser: Logical expressions (http.request|db.query)")
	fmt.Println("V2 Parser: Complex logic ((http.request|http.response)&api.v1.*)")
	fmt.Println("V2 Parser: V1 compatibility (http.request,db.query)")
	fmt.Println("\nBoth parsers have identical APIs - just change the import path!")
}
