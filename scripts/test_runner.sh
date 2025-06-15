#!/bin/bash

# Test runner for OVS Port Manager
set -e

echo "Running OVS Port Manager Tests..."
echo "=================================="

# Navigate to project root
cd "$(dirname "$0")"

echo ""
echo "1. Building project..."
if go build ./...; then
    echo "✓ Build successful"
else
    echo "✗ Build failed"
    exit 1
fi

echo ""
echo "2. Running unit tests..."
if go test ./internal/manager -v; then
    echo "✓ Unit tests passed"
else
    echo "✗ Unit tests failed"
    exit 1
fi

echo ""
echo "3. Running benchmarks..."
go test ./internal/manager -bench=. -benchmem

echo ""
echo "4. Running race detection tests..."
if go test ./internal/manager -race; then
    echo "✓ Race detection tests passed"
else
    echo "✗ Race detection tests failed"
    exit 1
fi

echo ""
echo "5. Test coverage..."
go test ./internal/manager -cover

echo ""
echo "All tests completed successfully! ✓"
