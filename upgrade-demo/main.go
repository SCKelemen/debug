package main

import (
	"fmt"
	"log/slog"
	"os"

	// To upgrade from V1 to V2, just change this import:
	// "github.com/SCKelemen/debug/v1/debug"
	"github.com/SCKelemen/debug/v2/debug"
)

func main() {
	fmt.Println("=== Upgrade Demo ===")
	fmt.Println("This demonstrates how easy it is to upgrade from V1 to V2")
	fmt.Println("Just change the import path - all code remains the same!")
	fmt.Println()

	// Create debug manager (same API for both V1 and V2)
	dm := debug.NewDebugManager()

	// Register flags (same API)
	flagDefinitions := []debug.FlagDefinition{
		{Flag: 1 << 0, Name: "http.request", Path: "http.request"},
		{Flag: 1 << 1, Name: "http.response", Path: "http.response"},
		{Flag: 1 << 2, Name: "db.query", Path: "db.query"},
		{Flag: 1 << 3, Name: "validation", Path: "validation"},
	}
	dm.RegisterFlags(flagDefinitions)

	// V1-style usage (works in both V1 and V2)
	fmt.Println("V1-style usage (comma-separated):")
	dm.SetFlags("http.*,db.query")
	dm.Log(1<<0, "HTTP request (V1 style)")
	dm.Log(1<<2, "DB query (V1 style)")
	fmt.Println()

	// V2-style usage (only works in V2)
	fmt.Println("V2-style usage (logical expressions):")
	dm.SetFlags("http.request|db.query")
	dm.Log(1<<0, "HTTP request (V2 style)")
	dm.Log(1<<2, "DB query (V2 style)")
	fmt.Println()

	// Complex V2 expressions
	fmt.Println("Complex V2 expressions:")
	dm.SetFlags("(http.*|db.*)&!validation")
	dm.Log(1<<0, "HTTP request (complex V2)")
	dm.Log(1<<2, "DB query (complex V2)")
	dm.Log(1<<3, "Validation (should not log - disabled)")
	fmt.Println()

	// Context system (same in both versions)
	fmt.Println("Context system (same API):")
	dm.SetFlags("http.*,db.*")
	dm.WithContext(1<<0, func() {
		dm.Log(1<<0, "HTTP request with context")
		dm.WithContext(1<<2, func() {
			dm.Log(1<<2, "DB query with nested context")
		})
	})
	fmt.Println()

	// Slog integration (same in both versions)
	fmt.Println("Slog integration (same API):")
	dm.EnableSlogWithHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dm.Log(1<<0, "Slog JSON output")
	dm.DisableSlog()
	fmt.Println()

	fmt.Println("=== Upgrade Complete ===")
	fmt.Println("To upgrade from V1 to V2:")
	fmt.Println("1. Change import: github.com/SCKelemen/debug/v1/debug -> github.com/SCKelemen/debug/v2/debug")
	fmt.Println("2. That's it! All your existing code continues to work")
	fmt.Println("3. Optionally, start using logical expressions for more complex flag combinations")
}
