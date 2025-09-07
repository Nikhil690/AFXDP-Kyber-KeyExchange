# Kyber-Benchmark Makefile

.PHONY: all build clean server client test deps run-example

# Build all binaries
all: build

# Build both server and client
build: server client

# Build server binary
server:
	@echo "Building server..."
	go build -o bin/server ./server

# Build client binary  
client:
	@echo "Building client..."
	go build -o bin/client ./client

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod tidy
	go mod download

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	go clean

# Run tests
test:
	@echo "Running tests..."
	go test ./...

# Create bin directory
bin:
	mkdir -p bin

# Build with bin directory
server: bin
	go build -o bin/server ./server

client: bin  
	go build -o bin/client ./client

# Run example benchmark
run-example: build
	@echo "Starting example benchmark..."
	@echo "Starting server in background..."
	./bin/server -verbose &
	@sleep 2
	@echo "Running client benchmark..."
	./bin/client -server localhost:8080 -size 1024 -count 1000 -verbose
	@echo "Stopping server..."
	@pkill -f "./bin/server" || true

# Run high-performance test
run-perf: build
	@echo "Starting performance test..."
	@echo "Starting server in background..."
	./bin/server &
	@sleep 2
	@echo "Running high-performance benchmark..."
	./bin/client -server localhost:8080 -size 32768 -count 10000 -workers 4
	@echo "Stopping server..."
	@pkill -f "./bin/server" || true

# Run crypto comparison test
run-crypto-test: build
	@echo "Starting crypto comparison test..."
	@echo "Test 1: With encryption"
	@echo "Starting server in background..."
	./bin/server -crypto=true &
	@sleep 2
	./bin/client -server localhost:8080 -crypto=true -size 1024 -count 5000
	@pkill -f "./bin/server" || true
	@sleep 1
	@echo "Test 2: Without encryption"
	@echo "Starting server in background..."
	./bin/server -crypto=false &
	@sleep 2
	./bin/client -server localhost:8080 -crypto=false -size 1024 -count 5000
	@pkill -f "./bin/server" || true

# Install required tools
install-tools:
	@echo "Installing development tools..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install golang.org/x/lint/golint@latest

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Lint code
lint:
	@echo "Linting code..."
	golint ./...
	go vet ./...

# Security check
security:
	@echo "Running security checks..."
	go list -json -m all | nancy sleuth

# Generate documentation
docs:
	@echo "Generating documentation..."
	godoc -http=:6060 &
	@echo "Documentation server started at http://localhost:6060"

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build all binaries"
	@echo "  build        - Build server and client"
	@echo "  server       - Build server binary"
	@echo "  client       - Build client binary"
	@echo "  deps         - Download dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  run-example  - Run example benchmark"
	@echo "  run-perf     - Run high-performance test"
	@echo "  run-crypto-test - Compare encrypted vs unencrypted"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  help         - Show this help"
