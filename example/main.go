package main

import (
	"fmt"
	"log"

	"github.com/SCKelemen/debug"
)

// Define your debug flags
const (
	// HTTP section
	DebugHTTPRequest debug.DebugFlag = 1 << iota
	DebugHTTPResponse
	DebugHTTPError
	debugHTTPEnd

	// Database section
	debugDBBegin
	DebugDBQuery
	DebugDBConnection
	DebugDBCache
	debugDBEnd

	// Processing section
	debugProcessingBegin
	DebugValidation
	DebugTransformation
	DebugSerialization
	debugProcessingEnd
)

func main() {
	// Create a new debug manager
	dm := debug.NewDebugManager()

	// Register your debug flags
	flagDefinitions := []debug.FlagDefinition{
		// HTTP flags
		{Flag: DebugHTTPRequest, Name: "http.request", Path: "http.request"},
		{Flag: DebugHTTPResponse, Name: "http.response", Path: "http.response"},
		{Flag: DebugHTTPError, Name: "http.error", Path: "http.error"},

		// Database flags
		{Flag: DebugDBQuery, Name: "db.query", Path: "db.query"},
		{Flag: DebugDBConnection, Name: "db.connection", Path: "db.connection"},
		{Flag: DebugDBCache, Name: "db.cache", Path: "db.cache"},

		// Processing flags
		{Flag: DebugValidation, Name: "validation", Path: "validation"},
		{Flag: DebugTransformation, Name: "transformation", Path: "transformation"},
		{Flag: DebugSerialization, Name: "serialization", Path: "serialization"},
	}

	dm.RegisterFlags(flagDefinitions)

	// Example 1: Enable specific flags
	fmt.Println("=== Example 1: Specific flags ===")
	err := dm.SetFlags("http.request,db.query")
	if err != nil {
		log.Fatal(err)
	}

	dm.Log(DebugHTTPRequest, "Processing HTTP request to /api/users")
	dm.Log(DebugHTTPResponse, "Sending response with 200 status") // This won't be logged
	dm.Log(DebugDBQuery, "Executing SELECT * FROM users")
	dm.Log(DebugValidation, "Validating user input") // This won't be logged

	// Example 2: Use glob patterns
	fmt.Println("\n=== Example 2: Glob patterns ===")
	err = dm.SetFlags("http.*")
	if err != nil {
		log.Fatal(err)
	}

	dm.Log(DebugHTTPRequest, "Processing HTTP request to /api/posts")
	dm.Log(DebugHTTPResponse, "Sending response with 201 status")
	dm.Log(DebugHTTPError, "HTTP error: 404 Not Found")
	dm.Log(DebugDBQuery, "Executing INSERT INTO posts") // This won't be logged

	// Example 3: Use severity levels
	fmt.Println("\n=== Example 3: Severity levels ===")
	err = dm.SetFlags("all")
	if err != nil {
		log.Fatal(err)
	}

	dm.SetSeverityFilter(debug.SeverityInfo) // Only show INFO and above

	dm.LogWithSeverity(DebugValidation, debug.SeverityTrace, "", "This is a trace message") // Won't be shown
	dm.LogWithSeverity(DebugValidation, debug.SeverityDebug, "", "This is a debug message") // Won't be shown
	dm.LogWithSeverity(DebugValidation, debug.SeverityInfo, "", "This is an info message")
	dm.LogWithSeverity(DebugValidation, debug.SeverityWarning, "", "This is a warning message")
	dm.LogWithSeverity(DebugValidation, debug.SeverityError, "", "This is an error message")

	// Example 4: Use context
	fmt.Println("\n=== Example 4: Context ===")
	dm.SetSeverityFilter(debug.SeverityTrace) // Show all messages

	dm.LogWithContext(DebugHTTPRequest, "user-service", "Processing request for user ID: %d", 12345)
	dm.LogWithContext(DebugDBQuery, "user-repository", "Querying user with ID: %d", 12345)

	// Example 5: Show enabled flags
	fmt.Println("\n=== Example 5: Enabled flags ===")
	err = dm.SetFlags("http.*,db.connection,validation")
	if err != nil {
		log.Fatal(err)
	}

	enabled := dm.GetEnabledFlags()
	fmt.Printf("Enabled flags: %v\n", enabled)

	available := dm.GetAvailableFlags()
	fmt.Printf("Available flags: %v\n", available)

	// Example 6: Custom path logging
	fmt.Println("\n=== Example 6: Custom path logging ===")
	dm.LogWithPath("custom.module", debug.SeverityInfo, "custom-context", "This is a custom path message")
	dm.LogWithPath("another.module.submodule", debug.SeverityDebug, "", "This is another custom path message")
}
