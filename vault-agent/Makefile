# Vault Agent CLI Makefile

# Variables
BINARY_NAME=vault-cli
CLI_BINARY_NAME=vault-cli
MAIN_PACKAGE=./main.go
CLI_MAIN_PACKAGE=./cmd/cli/main.go
BUILD_DIR=./build
VERSION?=1.0.0
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build targets
.PHONY: all build build-cli clean test test-coverage deps help

all: build build-cli

# Build the main vault agent
build:
	@echo "Building vault agent..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/vault-agent $(MAIN_PACKAGE)

# Build the CLI tool
build-cli:
	@echo "Building CLI tool..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_BINARY_NAME) $(CLI_MAIN_PACKAGE)

# Build for multiple platforms
build-all: build-linux build-darwin build-windows

build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)/linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/vault-agent $(MAIN_PACKAGE)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/linux/$(CLI_BINARY_NAME) $(CLI_MAIN_PACKAGE)

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)/darwin
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/vault-agent $(MAIN_PACKAGE)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/darwin/$(CLI_BINARY_NAME) $(CLI_MAIN_PACKAGE)

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)/windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/vault-agent.exe $(MAIN_PACKAGE)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/windows/$(CLI_BINARY_NAME).exe $(CLI_MAIN_PACKAGE)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Install CLI tool globally
install-cli: build-cli
	@echo "Installing CLI tool..."
	cp $(BUILD_DIR)/$(CLI_BINARY_NAME) /usr/local/bin/$(CLI_BINARY_NAME)
	chmod +x /usr/local/bin/$(CLI_BINARY_NAME)

# Generate shell completions
completions: build-cli
	@echo "Generating shell completions..."
	@mkdir -p $(BUILD_DIR)/completions
	$(BUILD_DIR)/$(CLI_BINARY_NAME) completion bash > $(BUILD_DIR)/completions/$(CLI_BINARY_NAME).bash
	$(BUILD_DIR)/$(CLI_BINARY_NAME) completion zsh > $(BUILD_DIR)/completions/$(CLI_BINARY_NAME).zsh
	$(BUILD_DIR)/$(CLI_BINARY_NAME) completion fish > $(BUILD_DIR)/completions/$(CLI_BINARY_NAME).fish

# Development helpers
dev-setup: deps
	@echo "Setting up development environment..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest

lint:
	@echo "Running linter..."
	golangci-lint run

format:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Docker targets
docker-build:
	@echo "Building Docker image..."
	docker build -t vault-agent:$(VERSION) .

docker-run: docker-build
	@echo "Running Docker container..."
	docker run -p 8080:8080 vault-agent:$(VERSION)

# Help
help:
	@echo "Available targets:"
	@echo "  build          - Build the vault agent"
	@echo "  build-cli      - Build the CLI tool"
	@echo "  build-all      - Build for all platforms"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  deps           - Install dependencies"
	@echo "  install-cli    - Install CLI tool globally"
	@echo "  completions    - Generate shell completions"
	@echo "  dev-setup      - Setup development environment"
	@echo "  lint           - Run linter"
	@echo "  format         - Format code"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  help           - Show this help"