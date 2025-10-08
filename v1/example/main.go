package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/SCKelemen/debug/v1/debug"
)

func main() {
	// Create a new V1 debug manager
	dm := debug.NewDebugManager()

	// Define some example flags
	flagDefinitions := []debug.FlagDefinition{
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

	fmt.Println("=== V1 Debug Manager Example ===")
	fmt.Println("V1 supports: comma-separated flags, globs, path-based severity filtering")
	fmt.Println("V1 does NOT support: logical expressions (|, &, !, ())")
	fmt.Println()

	// Example 1: Simple flag enablement
	fmt.Println("Example 1: Simple flag enablement")
	dm.SetFlags("http.request,db.query")
	dm.Log(1<<0, "Making HTTP request to /api/users")
	dm.Log(1<<2, "SELECT * FROM users WHERE active = true")
	dm.Log(1<<1, "HTTP response: 200 OK") // This won't log (not enabled)
	fmt.Println()

	// Example 2: Glob patterns
	fmt.Println("Example 2: Glob patterns")
	dm.SetFlags("http.*,db.*")
	dm.Log(1<<0, "HTTP request to /api/auth")
	dm.Log(1<<1, "HTTP response: 401 Unauthorized")
	dm.Log(1<<2, "Database query: SELECT user_id FROM sessions")
	dm.Log(1<<3, "Database connection established")
	dm.Log(1<<4, "API v1 auth login") // This won't log (not matching pattern)
	fmt.Println()

	// Example 3: Path-based severity filtering
	fmt.Println("Example 3: Path-based severity filtering")
	dm.SetFlags("http.*:ERROR,db.*:+WARN,validation:INFO|ERROR")
	dm.LogWithSeverity(1<<0, debug.SeverityInfo, "", "HTTP request info")     // Won't log (http.* only shows ERROR)
	dm.LogWithSeverity(1<<0, debug.SeverityError, "", "HTTP request failed")  // Will log
	dm.LogWithSeverity(1<<2, debug.SeverityInfo, "", "DB query info")         // Won't log (db.* shows WARN+)
	dm.LogWithSeverity(1<<2, debug.SeverityWarning, "", "DB query slow")      // Will log
	dm.LogWithSeverity(1<<7, debug.SeverityInfo, "", "Validation passed")     // Will log
	dm.LogWithSeverity(1<<7, debug.SeverityWarning, "", "Validation warning") // Won't log (validation only shows INFO|ERROR)
	fmt.Println()

	// Example 4: Context system
	fmt.Println("Example 4: Context system")
	dm.SetFlags("api.v1.auth.*,db.*")

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

	// Example 5: Slog integration
	fmt.Println("Example 5: Slog integration")
	dm.SetFlags("http.*")

	// Traditional logging
	fmt.Println("Traditional logging:")
	dm.Log(1<<0, "Traditional HTTP request")

	// Enable slog with text handler
	fmt.Println("\nSlog text handler:")
	dm.EnableSlog()
	dm.Log(1<<0, "Slog HTTP request")

	// Enable slog with JSON handler
	fmt.Println("\nSlog JSON handler:")
	dm.EnableSlogWithHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dm.Log(1<<0, "Slog JSON HTTP request")

	// Disable slog
	dm.DisableSlog()
	fmt.Println("\nBack to traditional logging:")
	dm.Log(1<<0, "Back to traditional")
	fmt.Println()

	// Example 6: V1 limitations demonstration
	fmt.Println("Example 6: V1 limitations (logical expressions not supported)")
	dm.SetFlags("http.request|db.query") // This will be treated as a single flag name, not a logical expression
	dm.Log(1<<0, "This won't log because 'http.request|db.query' is not a valid flag name")

	// To achieve OR logic in V1, you need to enable both flags separately
	dm.SetFlags("http.request,db.query") // V1 way: comma-separated
	dm.Log(1<<0, "This will log (http.request enabled)")
	dm.Log(1<<2, "This will also log (db.query enabled)")
	fmt.Println()

	fmt.Println("=== V1 Example Complete ===")
	fmt.Println("For logical expressions (|, &, !, ()), use the v2 package instead.")
}
