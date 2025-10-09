package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	debug "github.com/SCKelemen/debug"
	v2parser "github.com/SCKelemen/debug/v2/parser"
)

// WithDebugFlag adds a debug flag to the context (immutable, like standard Go context)
func WithDebugFlag(ctx context.Context, flag debug.DebugFlag, description string, dm *debug.DebugManager) context.Context {
	// Get existing flags from context
	existingFlags := debug.GetDebugFlagsFromContext(ctx)
	
	// Combine with new flag
	combinedFlags := existingFlags | flag
	
	// Create new context with combined flags
	newCtx := debug.WithDebugFlags(ctx, combinedFlags)
	
	return newCtx
}

// FunctionContext represents a function's debug context
type FunctionContext struct {
	dm   *debug.DebugManager
	flag debug.DebugFlag
	name string
}

// WithFunctionContext creates a new context with function marking
func WithFunctionContext(ctx context.Context, dm *debug.DebugManager, flag debug.DebugFlag, functionName string) (context.Context, *FunctionContext) {
	// Add function flag to context - inherits parent context
	newCtx := WithDebugFlag(ctx, flag, functionName, dm)

	// Log function entry
	dm.Log(newCtx, flag, "Function entry: %s", functionName)

	return newCtx, &FunctionContext{
		dm:   dm,
		flag: flag,
		name: functionName,
	}
}

// Cleanup logs function exit and can be used with defer
func (fc *FunctionContext) Cleanup() {
	fc.dm.Log(context.Background(), fc.flag, "Function exit: %s", fc.name)
}

// CleanupWithError logs function exit with error
func (fc *FunctionContext) CleanupWithError(err error) {
	if err != nil {
		fc.dm.Log(context.Background(), fc.flag, "Function exit with error: %s - %v", fc.name, err)
	} else {
		fc.dm.Log(context.Background(), fc.flag, "Function exit: %s", fc.name)
	}
}

// Business logic functions with context marking
func ProcessUserRegistration(ctx context.Context, dm *debug.DebugManager, userData map[string]string) error {
	// Mark this function in context
	ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<5), "ProcessUserRegistration")
	defer fc.Cleanup()

	// Log function start
	dm.Log(ctx, 1<<5, "Starting user registration process")

	// Validate user data
	if err := ValidateUserData(ctx, dm, userData); err != nil {
		fc.CleanupWithError(err)
		return err
	}

	// Create user account
	if err := CreateUserAccount(ctx, dm, userData); err != nil {
		fc.CleanupWithError(err)
		return err
	}

	// Send welcome email
	if err := SendWelcomeEmail(ctx, dm, userData["email"]); err != nil {
		fc.CleanupWithError(err)
		return err
	}

	// Log successful completion
	dm.Log(ctx, 1<<5, "User registration completed successfully")
	return nil
}

func ValidateUserData(ctx context.Context, dm *debug.DebugManager, userData map[string]string) error {
	// Mark this function in context
	ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<6), "ValidateUserData")
	defer fc.Cleanup()

	// Log validation start
	dm.Log(ctx, 1<<6, "Starting user data validation")

	// Check required fields
	requiredFields := []string{"email", "name", "password"}
	for _, field := range requiredFields {
		if userData[field] == "" {
			err := fmt.Errorf("missing required field: %s", field)
			fc.CleanupWithError(err)
			return err
		}
		dm.Log(ctx, 1<<6, "Validated field: %s", field)
	}

	// Simulate validation work
	time.Sleep(5 * time.Millisecond)

	// Log validation success
	dm.Log(ctx, 1<<6, "User data validation completed successfully")
	return nil
}

func CreateUserAccount(ctx context.Context, dm *debug.DebugManager, userData map[string]string) error {
	// Mark this function in context
	ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<7), "CreateUserAccount")
	defer fc.Cleanup()

	// Log account creation start
	dm.Log(ctx, 1<<7, "Starting user account creation")

	// Hash password
	if err := HashPassword(ctx, dm, userData["password"]); err != nil {
		fc.CleanupWithError(err)
		return err
	}

	// Save to database
	if err := SaveUserToDatabase(ctx, dm, userData); err != nil {
		fc.CleanupWithError(err)
		return err
	}

	// Log account creation success
	dm.Log(ctx, 1<<7, "User account created successfully")
	return nil
}

func HashPassword(ctx context.Context, dm *debug.DebugManager, password string) error {
	// Mark this function in context
	ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<8), "HashPassword")
	defer fc.Cleanup()

	// Log password hashing
	dm.Log(ctx, 1<<8, "Hashing password (length: %d)", len(password))

	// Simulate password hashing
	time.Sleep(10 * time.Millisecond)

	// Log hashing completion
	dm.Log(ctx, 1<<8, "Password hashed successfully")
	return nil
}

func SaveUserToDatabase(ctx context.Context, dm *debug.DebugManager, userData map[string]string) error {
	// Mark this function in context
	ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<9), "SaveUserToDatabase")
	defer fc.Cleanup()

	// Log database save
	dm.Log(ctx, 1<<9, "Saving user to database: %s", userData["email"])

	// Simulate database save
	time.Sleep(15 * time.Millisecond)

	// Log save completion
	dm.Log(ctx, 1<<9, "User saved to database successfully")
	return nil
}

func SendWelcomeEmail(ctx context.Context, dm *debug.DebugManager, email string) error {
	// Mark this function in context
	ctx, fc := WithFunctionContext(ctx, dm, debug.DebugFlag(1<<10), "SendWelcomeEmail")
	defer fc.Cleanup()

	// Log email sending
	dm.Log(ctx, 1<<10, "Sending welcome email to: %s", email)

	// Simulate email sending
	time.Sleep(20 * time.Millisecond)

	// Log email sent
	dm.Log(ctx, 1<<10, "Welcome email sent successfully")
	return nil
}

func main() {
	// Define debug flags
	flagDefs := []debug.FlagDefinition{
		{Flag: 1 << 5, Name: "user.registration", Path: "user.registration"},
		{Flag: 1 << 6, Name: "user.validation", Path: "user.validation"},
		{Flag: 1 << 7, Name: "user.account", Path: "user.account"},
		{Flag: 1 << 8, Name: "user.password", Path: "user.password"},
		{Flag: 1 << 9, Name: "user.database", Path: "user.database"},
		{Flag: 1 << 10, Name: "user.email", Path: "user.email"},
	}

	// Create debug manager with JSON logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	dm := debug.NewDebugManagerWithSlogHandler(v2parser.NewParser(), handler)
	dm.RegisterFlags(flagDefs)

	// Enable debug flags - show all user-related functions
	dm.SetFlags("user.*")

	fmt.Println("=== Function-Level Context Marking Example ===")
	fmt.Println("This example shows how to mark functions in context")
	fmt.Println("with automatic entry/exit logging and cleanup.")
	fmt.Println()

	// Test successful user registration
	fmt.Println("--- Successful User Registration ---")
	userData := map[string]string{
		"email":    "john@example.com",
		"name":     "John Doe",
		"password": "securepassword123",
	}

	ctx := context.Background()
	if err := ProcessUserRegistration(ctx, dm, userData); err != nil {
		fmt.Printf("Registration failed: %v\n", err)
	} else {
		fmt.Println("Registration completed successfully!")
	}

	fmt.Println()
	fmt.Println("--- Failed User Registration (missing email) ---")
	invalidUserData := map[string]string{
		"name":     "Jane Doe",
		"password": "securepassword123",
		// Missing email
	}

	if err := ProcessUserRegistration(ctx, dm, invalidUserData); err != nil {
		fmt.Printf("Registration failed as expected: %v\n", err)
	}

	fmt.Println()
	fmt.Println("=== Function Context Benefits ===")
	fmt.Println("1. Automatic function entry/exit logging")
	fmt.Println("2. Context flows through function calls")
	fmt.Println("3. Easy cleanup with defer statements")
	fmt.Println("4. Error handling with context")
	fmt.Println("5. Hierarchical function tracing")
	fmt.Println("6. Each function can have its own debug flag")
}
