# Parachute Makefile

.PHONY: all build test test-unit test-integration clean docker docker-up docker-down lint fmt help

# Build variables
BINARY_NAME=parachute
BUILD_DIR=./build
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Go settings
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Default target
all: build

## Build targets

build: ## Build the binary
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/parachute

build-linux: ## Build for Linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/parachute

build-darwin: ## Build for macOS
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/parachute
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/parachute

## Test targets

test: test-unit ## Run all tests

test-unit: ## Run unit tests
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-coverage: test-unit ## Run tests with coverage report
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-integration: ## Run integration tests with Docker
	@echo "Starting integration test environment..."
	cd tests/integration && docker compose -f docker-compose.test.yml up --build -d
	@echo "Waiting for services to start..."
	@sleep 10
	@echo "Running integration tests..."
	cd tests/integration && ./run_tests.sh || (docker compose -f docker-compose.test.yml logs && exit 1)
	@echo ""
	@echo "Running network isolation tests (from inside agent container)..."
	cd tests/integration && docker compose -f docker-compose.test.yml logs test-agent
	@echo ""
	@echo "Verifying network isolation test results..."
	cd tests/integration && docker compose -f docker-compose.test.yml logs test-agent 2>&1 | grep -q "All network isolation tests passed" || (echo "Network isolation tests failed!" && docker compose -f docker-compose.test.yml logs && exit 1)
	@echo "Cleaning up..."
	cd tests/integration && docker compose -f docker-compose.test.yml down -v

test-integration-logs: ## Show integration test logs
	cd tests/integration && docker compose -f docker-compose.test.yml logs -f

## Docker targets

docker: ## Build Docker image
	docker build -t parachute:$(VERSION) -t parachute:latest .

docker-up: ## Start with Docker Compose
	docker compose up -d

docker-down: ## Stop Docker Compose
	docker compose down

docker-logs: ## Show Docker Compose logs
	docker compose logs -f

docker-hardened: ## Start with hardened profile
	docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d

## Development targets

run: build ## Run locally
	$(BUILD_DIR)/$(BINARY_NAME) --config parachute.yaml

dev: ## Run with hot reload (requires air)
	air

fmt: ## Format code
	$(GOFMT) ./...

lint: ## Run linters
	$(GOVET) ./...
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipping..."; \
	fi

## Utility targets

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	cd tests/integration && docker compose -f docker-compose.test.yml down -v 2>/dev/null || true

deps: ## Download dependencies
	$(GOCMD) mod download
	$(GOCMD) mod tidy

generate: ## Run go generate
	$(GOCMD) generate ./...

## Help

help: ## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
