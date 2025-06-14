#!/bin/bash
set -e

# Change to the project root directory
cd "$(dirname "$0")/.."

echo "Testing multi-architecture Docker builds..."

# Test AMD64 build
echo "Building for linux/amd64..."
docker buildx build --platform linux/amd64 --load -t ovs-port-manager:amd64 .

# Test ARM64 build
echo "Building for linux/arm64..."
docker buildx build --platform linux/arm64 --load -t ovs-port-manager:arm64 .

# Test multi-platform build (without loading since we can't load multi-platform)
echo "Building multi-platform (amd64 and arm64)..."
docker buildx build --platform linux/amd64,linux/arm64 -t ovs-port-manager:multiarch .

echo "Multi-architecture builds completed successfully!"

# Show the images
echo "Built images:"
docker images | grep ovs-port-manager
