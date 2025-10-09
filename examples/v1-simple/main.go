package main

import (
	"context"
	"fmt"

	debug "github.com/SCKelemen/debug"
	v1parser "github.com/SCKelemen/debug/v1/parser"
)

func main() {
	// Define some debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: 1 << 4, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
	}

	fmt.Println("=== V1 Parser Example (Simple Comma-Separated) ===")

	// Create V1 debug manager with traditional logging
	dm := debug.NewDebugManager(v1parser.NewParser())
	dm.RegisterFlags(flagDefs)

	// Enable flags using V1 comma-separated syntax
	dm.SetFlags("http.*,db.query")

	// Create context with debug flags
	ctx := debug.WithDebugFlags(context.Background(), debug.DebugFlag(1<<3)) // api.v1.auth.login

	// Log some messages
	dm.Log(ctx, 1<<0, "Processing HTTP request")  // http.request
	dm.Log(ctx, 1<<1, "Processing HTTP response") // http.response
	dm.Log(ctx, 1<<2, "Executing database query") // db.query
	dm.Log(ctx, 1<<3, "API authentication")       // api.v1.auth.login

	fmt.Println()

	// Example with severity filtering
	fmt.Println("=== V1 Parser with Severity Filtering ===")
	dm2 := debug.NewDebugManager(v1parser.NewParser())
	dm2.RegisterFlags(flagDefs)

	// Enable flags with severity filtering
	dm2.SetFlags("http.*:ERROR,db.query:+WARN")

	dm2.LogWithSeverity(ctx, 1<<0, debug.SeverityError, "http.request", "HTTP request error")
	dm2.LogWithSeverity(ctx, 1<<1, debug.SeverityInfo, "http.response", "HTTP response info") // Won't log (not ERROR)
	dm2.LogWithSeverity(ctx, 1<<2, debug.SeverityWarning, "db.query", "DB query warning")
	dm2.LogWithSeverity(ctx, 1<<2, debug.SeverityError, "db.query", "DB query error") // Will log (WARN+)
}
