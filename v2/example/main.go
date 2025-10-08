package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/SCKelemen/debug/v2"
)

func main() {
	// Create a new V2 debug manager
	dm := v2.NewDebugManager()

	// Define some example flags
	flagDefinitions := []v2.FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "db.connection", Path: "db.connection"},
		{Flag: 1 << 4, Name: "api.v1.auth.login", Path: "api.v1.auth.login"},
		{Flag: 1 << 5, Name: "api.v1.auth.logout", Path: "api.v1.auth.logout"},
		{Flag: 1 << 6, Name: "api.v2.auth.login", Path: "api.v2.auth.login"},
		{Flag: 1 << 7, Name: "validation", Path: "validation"},
	}

	dm.RegisterFlags(flagDefinitions)

	fmt.Println("=== V2 Debug Manager Example ===")
	fmt.Println("V2 supports: everything from V1 PLUS logical expressions (|, &, !, ())")
	fmt.Println()

	// Example 1: V1 compatibility (comma-separated flags)
	fmt.Println("Example 1: V1 compatibility (comma-separated flags)")
	dm.SetFlags("http.request,db.query")
	dm.Log(1<<0, "Making HTTP request to /api/users")
	dm.Log(1<<2, "SELECT * FROM users WHERE active = true")
	dm.Log(1<<1, "HTTP response: 200 OK") // This won't log (not enabled)
	fmt.Println()

	// Example 2: V2 logical expressions - OR
	fmt.Println("Example 2: V2 logical expressions - OR (|)")
	dm.SetFlags("http.request|db.query")
	dm.Log(1<<0, "HTTP request (enabled by OR expression)")
	dm.Log(1<<2, "Database query (enabled by OR expression)")
	dm.Log(1<<1, "HTTP response (not enabled)") // This won't log
	fmt.Println()

	// Example 3: V2 logical expressions - AND
	fmt.Println("Example 3: V2 logical expressions - AND (&)")
	dm.SetFlags("http.request&db.query")
	dm.Log(1<<0, "HTTP request (won't log - AND requires both flags)")
	dm.Log(1<<2, "Database query (won't log - AND requires both flags)")
	
	// Enable both flags to see AND behavior
	dm.SetFlags("http.request,db.query") // Enable both
	dm.SetFlags("http.request&db.query") // Now apply AND filter
	dm.Log(1<<0, "HTTP request (now logs - both flags enabled)")
	dm.Log(1<<2, "Database query (now logs - both flags enabled)")
	fmt.Println()

	// Example 4: V2 logical expressions - NOT
	fmt.Println("Example 4: V2 logical expressions - NOT (!)")
	dm.SetFlags("!http.request") // Enable everything except http.request
	dm.Log(1<<0, "HTTP request (won't log - explicitly disabled)")
	dm.Log(1<<2, "Database query (will log - not disabled)")
	dm.Log(1<<1, "HTTP response (will log - not disabled)")
	fmt.Println()

	// Example 5: V2 logical expressions - Complex combinations
	fmt.Println("Example 5: V2 logical expressions - Complex combinations")
	dm.SetFlags("(http.request|db.query)&!validation")
	dm.Log(1<<0, "HTTP request (logs - matches OR and not validation)")
	dm.Log(1<<2, "Database query (logs - matches OR and not validation)")
	dm.Log(1<<7, "Validation (won't log - explicitly disabled)")
	dm.Log(1<<1, "HTTP response (won't log - not in OR clause)")
	fmt.Println()

	// Example 6: V2 with path-based severity filtering
	fmt.Println("Example 6: V2 with path-based severity filtering")
	dm.SetFlags("(http.*|db.*):ERROR")
	dm.LogWithSeverity(1<<0, v2.SeverityInfo, "", "HTTP request info")     // Won't log (only ERROR)
	dm.LogWithSeverity(1<<0, v2.SeverityError, "", "HTTP request failed")  // Will log
	dm.LogWithSeverity(1<<2, v2.SeverityInfo, "", "DB query info")         // Won't log (only ERROR)
	dm.LogWithSeverity(1<<2, v2.SeverityError, "", "DB query failed")      // Will log
	dm.LogWithSeverity(1<<7, v2.SeverityError, "", "Validation error")     // Won't log (not in pattern)
	fmt.Println()

	// Example 7: Context system with V2
	fmt.Println("Example 7: Context system with V2")
	dm.SetFlags("api.v1.auth.*|db.*")
	
	// Simulate an API handler with context
	dm.WithContext(1<<4, func() { // api.v1.auth.login context
		dm.Log(1<<4, "Starting auth login process")
		
		// Nested context for database operations
		dm.WithContext(1<<2, func() { // db.query context
			dm.Log(1<<2, "Querying user credentials")
			dm.Log(1<<3, "Establishing DB connection")
		})
		
		dm.Log(1<<4, "Auth login completed")
	})
	fmt.Println()

	// Example 8: Slog integration with V2
	fmt.Println("Example 8: Slog integration with V2")
	dm.SetFlags("http.request|db.query")
	
	// Traditional logging
	fmt.Println("Traditional logging:")
	dm.Log(1<<0, "Traditional HTTP request")
	dm.Log(1<<2, "Traditional DB query")
	
	// Enable slog with text handler
	fmt.Println("\nSlog text handler:")
	dm.EnableSlog()
	dm.Log(1<<0, "Slog HTTP request")
	dm.Log(1<<2, "Slog DB query")
	
	// Enable slog with JSON handler
	fmt.Println("\nSlog JSON handler:")
	dm.EnableSlogWithHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dm.Log(1<<0, "Slog JSON HTTP request")
	dm.Log(1<<2, "Slog JSON DB query")
	
	// Disable slog
	dm.DisableSlog()
	fmt.Println("\nBack to traditional logging:")
	dm.Log(1<<0, "Back to traditional")
	fmt.Println()

	// Example 9: Advanced V2 expressions
	fmt.Println("Example 9: Advanced V2 expressions")
	dm.SetFlags("api.v1.auth.*|(http.*&!http.response)")
	dm.Log(1<<4, "API v1 auth login (matches first part of OR)")
	dm.Log(1<<5, "API v1 auth logout (matches first part of OR)")
	dm.Log(1<<0, "HTTP request (matches second part of OR)")
	dm.Log(1<<1, "HTTP response (won't log - explicitly disabled in second part)")
	dm.Log(1<<2, "DB query (won't log - not in expression)")
	fmt.Println()

	fmt.Println("=== V2 Example Complete ===")
	fmt.Println("V2 provides full logical expression support while maintaining V1 compatibility.")
}
