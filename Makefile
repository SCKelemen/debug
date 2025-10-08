.PHONY: test example clean fmt vet

# Run tests
test:
	go test -v ./...

# Run example
example:
	go run example/main.go

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
