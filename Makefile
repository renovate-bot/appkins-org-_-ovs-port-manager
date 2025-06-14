# Makefile for OVS Port Manager

# Variables
BINARY_NAME=ovs-port-manager
DOCKER_IMAGE=ovs-port-manager
VERSION?=latest

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

.PHONY: all build clean test deps docker docker-build docker-run help

# Default target
all: deps build

# Build the binary
build:
	$(GOBUILD) -o $(BINARY_NAME) -v

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

# Run tests
test:
	$(GOTEST) -v ./...

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE):$(VERSION) .

# Run with Docker Compose
docker-run:
	docker-compose up --build

# Stop Docker Compose
docker-stop:
	docker-compose down

# Test netlink functionality (requires root)
test-netlink:
	@echo "Testing netlink functionality (requires root privileges)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Please run with sudo: sudo make test-netlink"; \
		exit 1; \
	fi
	./hack/test-netlink.sh

# Install (copy to /usr/local/bin)
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin (requires root)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Please run with sudo: sudo make install"; \
		exit 1; \
	fi
	cp $(BINARY_NAME) /usr/local/bin/
	chmod +x /usr/local/bin/$(BINARY_NAME)

# Uninstall
uninstall:
	@echo "Removing $(BINARY_NAME) from /usr/local/bin (requires root)..."
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Please run with sudo: sudo make uninstall"; \
		exit 1; \
	fi
	rm -f /usr/local/bin/$(BINARY_NAME)

# Format code
fmt:
	go fmt ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which docker >/dev/null || (echo "Docker not found. Please install Docker." && exit 1)
	@which ovs-vsctl >/dev/null || (echo "OVS not found. Please install Open vSwitch." && exit 1)
	@echo "All dependencies found."

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Download dependencies and build"
	@echo "  build        - Build the binary"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker Compose"
  test-netlink - Test netlink functionality (requires root)"
	@echo "  install      - Install to /usr/local/bin (requires root)"
	@echo "  uninstall    - Remove from /usr/local/bin (requires root)"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code (requires golangci-lint)"
	@echo "  check-deps   - Check if dependencies are installed"
	@echo "  help         - Show this help message"
