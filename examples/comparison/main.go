package main

import (
	"context"
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

	// Create context with debug flags
	ctx := debug.WithDebugFlags(context.Background(), debug.DebugFlag(1<<3)) // api.v1.auth.login

	fmt.Println("=== V1 vs V2 Parser Comparison ===")

	// V1 Parser - Simple comma-separated
	fmt.Println("\n--- V1 Parser (Simple) ---")
	dm1 := debug.NewDebugManager(v1parser.NewParser())
	dm1.RegisterFlags(flagDefs)
	dm1.SetFlags("http.*,db.query")

	dm1.Log(ctx, 1<<0, "HTTP request with V1")
	dm1.Log(ctx, 1<<1, "HTTP response with V1")
	dm1.Log(ctx, 1<<2, "DB query with V1")

	// V2 Parser - Logical expressions
	fmt.Println("\n--- V2 Parser (Logical Expressions) ---")
	dm2 := debug.NewDebugManager(v2parser.NewParser())
	dm2.RegisterFlags(flagDefs)
	dm2.SetFlags("http.request|db.query") // Same result as V1

	dm2.Log(ctx, 1<<0, "HTTP request with V2")
	dm2.Log(ctx, 1<<1, "HTTP response with V2") // Won't log (not in expression)
	dm2.Log(ctx, 1<<2, "DB query with V2")

	// V2 Parser - Complex logical expressions
	fmt.Println("\n--- V2 Parser (Complex Logic) ---")
	dm3 := debug.NewDebugManager(v2parser.NewParser())
	dm3.RegisterFlags(flagDefs)
	dm3.SetFlags("(http.request|http.response)&api.v1.*")

	dm3.Log(ctx, 1<<0, "HTTP request in API context")  // Will log
	dm3.Log(ctx, 1<<1, "HTTP response in API context") // Will log
	dm3.Log(ctx, 1<<2, "DB query in API context")      // Won't log (not http.*)

	// V2 Parser - V1 compatibility
	fmt.Println("\n--- V2 Parser (V1 Compatibility) ---")
	dm4 := debug.NewDebugManager(v2parser.NewParser())
	dm4.RegisterFlags(flagDefs)
	dm4.SetFlags("http.request,db.query") // V1 syntax in V2 parser

	dm4.Log(ctx, 1<<0, "HTTP request with V1 syntax in V2")
	dm4.Log(ctx, 1<<2, "DB query with V1 syntax in V2")

	fmt.Println("\n=== Summary ===")
	fmt.Println("V1 Parser: Simple comma-separated flags (http.*,db.query)")
	fmt.Println("V2 Parser: Logical expressions (http.request|db.query)")
	fmt.Println("V2 Parser: Complex logic ((http.request|http.response)&api.v1.*)")
	fmt.Println("V2 Parser: V1 compatibility (http.request,db.query)")
	fmt.Println("\nBoth parsers have identical APIs - just change the import path!")
}
