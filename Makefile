# Parachute Makefile

.PHONY: all build build-verify test test-unit test-integration clean docker docker-up docker-down docker-demo demo demo-down lint fmt helm-lint demo-telemetry demo-telemetry-down demo-telemetry-logs demo-telemetry-test help

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

build-verify: ## Build the audit log verification tool
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/parachute-verify ./cmd/parachute-verify

build-all: build build-verify ## Build all binaries

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

## Demo targets

demo: ## Start demo environment
	docker compose -f docker-compose.demo.yml up --build -d
	@echo "Demo running! Dashboard at http://localhost:8080/dashboard/"

demo-down: ## Stop demo environment
	docker compose -f docker-compose.demo.yml down -v

demo-logs: ## Show demo logs
	docker compose -f docker-compose.demo.yml logs -f

## Helm targets

helm-lint: ## Lint Helm chart
	helm lint deploy/helm/parachute/

helm-template: ## Render Helm templates locally
	helm template parachute deploy/helm/parachute/

helm-dry-run: ## Dry-run Helm install
	helm install parachute deploy/helm/parachute/ --dry-run

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
	docker compose -f docker-compose.demo.yml down -v 2>/dev/null || true
	docker compose -f docker-compose.telemetry-demo.yml down -v 2>/dev/null || true

deps: ## Download dependencies
	$(GOCMD) mod download
	$(GOCMD) mod tidy

generate: ## Run go generate
	$(GOCMD) generate ./...

## Telemetry demo targets

demo-telemetry: ## Start telemetry pipeline demo (sidecar + Pro + Postgres)
	docker compose -f docker-compose.telemetry-demo.yml up --build -d
	@echo ""
	@echo "Waiting for stack to be ready..."
	@sleep 10
	@echo ""
	@echo "Stack is ready!"
	@echo "  Sidecar dashboard: http://localhost:8080/dashboard/"
	@echo "  Pro control plane: http://localhost:8443"
	@echo ""
	@echo "Send a test MCP tool call:"
	@echo '  curl -u admin:demo -X POST http://localhost:8080/mcp \'
	@echo '    -H "Content-Type: application/json" \'
	@echo '    -d '"'"'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"Read","arguments":{"path":"/tmp/test"}},"id":1}'"'"''

demo-telemetry-down: ## Stop telemetry pipeline demo
	docker compose -f docker-compose.telemetry-demo.yml down -v

demo-telemetry-logs: ## Show telemetry demo logs
	docker compose -f docker-compose.telemetry-demo.yml logs -f

demo-telemetry-test: ## Run telemetry integration test
	./tests/integration/telemetry_test.sh

## Help

help: ## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
