# Build stage - use Alpine for better multi-arch support
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# Automatically provided by Docker when using buildx
ARG TARGETOS
ARG TARGETARCH
ARG BUILDPLATFORM

# Install build dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    tzdata

WORKDIR /app

# Copy go mod files first (for better caching)
COPY go.mod go.sum ./

# Copy source code
COPY internal/ ./internal/
COPY cmd/ ./cmd/

# Download dependencies with verbose output
RUN go mod download && go mod verify

# Build the application with proper multi-architecture support
# Use conditional logic to handle different architectures more robustly
RUN set -e; \
    echo "Building for ${TARGETOS}/${TARGETARCH}"; \
    export CGO_ENABLED=0; \
    export GOOS=${TARGETOS:-linux}; \
    export GOARCH=${TARGETARCH:-amd64}; \
    go build \
        -v \
        -ldflags='-w -s -extldflags "-static"' \
        -o ovs-port-manager ./cmd/ovs-port-manager

# Final stage: scratch container for minimal size
FROM scratch

# Copy CA certificates for HTTPS (if needed)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data (if needed)
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the static binary
COPY --from=builder /app/ovs-port-manager /ovs-port-manager

# Copy the default configuration file
COPY ovs-port-manager.yaml ./

# Labels for metadata
LABEL maintainer="appkins-org" \
      description="OVS Port Manager for Docker containers - Minimal scratch image" \
      version="1.0"

# Use the binary as entrypoint
ENTRYPOINT ["/ovs-port-manager"]
