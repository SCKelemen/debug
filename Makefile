.PHONY: test examples clean fmt vet

# Run tests (excluding examples directory)
test:
	go test -v ./v1/parser ./v2/parser .

# Run examples
examples:
	@echo "=== Running V1 Simple Example ==="
	go run ./examples/v1-simple.go
	@echo "\n=== Running V2 Features Example ==="
	go run ./examples/v2-features.go
	@echo "\n=== Running Comparison Example ==="
	go run ./examples/comparison.go

# Run basic example
example:
	go run ./examples/basic.go

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Clean build artifacts
clean:
	go clean

# Run all checks
check: fmt vet test

# Install dependencies
deps:
	go mod tidy
	go mod download
