package main

import (
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

	// Create method contexts for different operations
	mc1 := dm.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc1.Info("Processing HTTP request")

	mc2 := dm.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc2.Info("Processing HTTP response")

	mc3 := dm.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc3.Info("Executing database query")

	mc4 := dm.WithMethodContext(debug.DebugFlag(1 << 3)) // api.v1.auth.login
	mc4.Info("API authentication")

	fmt.Println()

	// Example with severity filtering
	fmt.Println("=== V1 Parser with Severity Filtering ===")
	dm2 := debug.NewDebugManager(v1parser.NewParser())
	dm2.RegisterFlags(flagDefs)

	// Enable flags with severity filtering
	dm2.SetFlags("http.*:ERROR,db.query:+WARN")

	// Create method contexts for different operations with severity filtering
	mc5 := dm2.WithMethodContext(debug.DebugFlag(1 << 0)) // http.request
	mc5.Error("HTTP request error")

	mc6 := dm2.WithMethodContext(debug.DebugFlag(1 << 1)) // http.response
	mc6.Info("HTTP response info")                        // Won't log (not ERROR)

	mc7 := dm2.WithMethodContext(debug.DebugFlag(1 << 2)) // db.query
	mc7.Warn("DB query warning")
	mc7.Error("DB query error") // Will log (WARN+)
}
