.PHONY: test test-short test-verbose test-coverage test-race clean build help install

# Default target
help:
	@echo "Available targets:"
	@echo "  make test          - Run all tests"
	@echo "  make test-short    - Run tests in short mode (skip slow tests)"
	@echo "  make test-verbose  - Run tests with verbose output"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make test-race     - Run tests with race detector"
	@echo "  make build         - Build the binary"
	@echo "  make install       - Install pre-requisite tools"
	@echo "  make clean         - Remove build artifacts and test files"
	@echo ""
	@echo "Examples:"
	@echo "  make test-short              # Quick test run"
	@echo "  make test-coverage           # Generate coverage report"
	@echo "  make test TEST_ARGS='-v'     # Custom test arguments"

# Run all tests
test:
	@echo "Running all tests..."
	go test ./...

# Run tests in short mode
test-short:
	@echo "Running tests in short mode..."
	go test -short ./...

# Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -short -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	go test -short -race ./...

# Run tests for specific package
test-package:
	@echo "Running tests for specific package..."
	@read -p "Enter package path (e.g., ./internal/utils): " pkg; \
	go test -v -short $$pkg

# Run a specific test
test-one:
	@echo "Running specific test..."
	@read -p "Enter package path: " pkg; \
	read -p "Enter test name: " test; \
	go test -v -short -run $$test $$pkg

# Build the binary with version info
build:
	@echo "Building enumeraga..."
	@VERSION=$$(git describe --tags --always --dirty 2>/dev/null || echo "dev"); \
	COMMIT=$$(git rev-parse HEAD 2>/dev/null || echo "unknown"); \
	DATE=$$(date -u '+%Y-%m-%d_%H:%M:%S'); \
	go build -ldflags="-X github.com/0x5ubt13/enumeraga/internal/utils.Version=$$VERSION \
		-X github.com/0x5ubt13/enumeraga/internal/utils.GitCommit=$$COMMIT \
		-X github.com/0x5ubt13/enumeraga/internal/utils.BuildDate=$$DATE" \
		-o enumeraga main.go
	@echo "Build complete: ./enumeraga (version: $$VERSION)"

# Install pre-requisite tools
install:
	@echo "Installing pre-requisite tools..."
	./enumeraga infra -i

# Clean build artifacts and test files
clean:
	@echo "Cleaning up..."
	rm -f enumeraga
	rm -f coverage.out coverage.html
	rm -f test_resolve_manual.go.bak
	go clean -testcache
	@echo "Cleanup complete"

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Check test coverage by package
coverage-by-package:
	@echo "Test coverage by package:"
	@go test -short -coverprofile=coverage.out ./... 2>&1 | grep coverage: | sort -t: -k1
