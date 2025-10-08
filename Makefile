.PHONY: test example-v1 example-v2 upgrade-demo clean fmt vet

# Run tests
test:
	go test -v ./v1/debug/...
	go test -v ./v2/debug/...

# Run V1 example
example-v1:
	cd v1/example && go run main.go

# Run V2 example
example-v2:
	cd v2/example && go run main.go

# Run upgrade demo
upgrade-demo:
	cd upgrade-demo && go run main.go

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
