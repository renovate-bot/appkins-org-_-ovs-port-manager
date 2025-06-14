# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ovs-port-manager .

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    openvswitch \
    iproute2 \
    util-linux \
    sudo

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/ovs-port-manager .

# Create necessary directories
RUN mkdir -p /var/run/netns

# Set proper permissions
RUN chmod +x ovs-port-manager

# Expose Docker socket (will be mounted as volume)
VOLUME ["/var/run/docker.sock"]

# Run as root (required for network operations)
USER root

# Start the application
CMD ["./ovs-port-manager"]
