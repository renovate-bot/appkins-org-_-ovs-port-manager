#!/bin/bash

# Example script demonstrating OVS Port Manager usage

set -e

echo "=== OVS Port Manager Demo ==="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root for OVS operations"
   exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo "Cleaning up..."
    docker stop ovs-demo-nginx ovs-demo-python 2>/dev/null || true
    docker rm ovs-demo-nginx ovs-demo-python 2>/dev/null || true
    ovs-vsctl --if-exists del-br demo-bridge 2>/dev/null || true
}

trap cleanup EXIT

echo "1. Setting up OVS bridge..."
ovs-vsctl --may-exist add-br demo-bridge
ovs-vsctl set bridge demo-bridge other-config:hwaddr=02:42:ac:11:00:01

echo "2. Starting OVS Port Manager in background..."
./ovs-port-manager &
MANAGER_PID=$!

# Give the manager time to start
sleep 3

echo "3. Starting first container with OVS configuration..."
docker run -d \
    --name ovs-demo-nginx \
    --label ovs.ip_address=10.0.1.10/24 \
    --label ovs.bridge=demo-bridge \
    --label ovs.gateway=10.0.1.1 \
    nginx:latest

echo "4. Starting second container with different OVS configuration..."
docker run -d \
    --name ovs-demo-python \
    --label ovs.ip_address=10.0.1.11/24 \
    --label ovs.bridge=demo-bridge \
    --label ovs.gateway=10.0.1.1 \
    --label ovs.mtu=1400 \
    python:3.9-alpine \
    python -c "import http.server; http.server.test(port=8000)"

echo "5. Waiting for containers to start..."
sleep 5

echo "6. Checking OVS configuration..."
echo "OVS bridges:"
ovs-vsctl list-br

echo -e "\nOVS ports on demo-bridge:"
ovs-vsctl list-ports demo-bridge

echo -e "\nOVS interface details:"
ovs-vsctl show

echo "7. Testing connectivity (if bridge is configured with IP)..."
echo "You can now configure the bridge with an IP and test connectivity:"
echo "  ip addr add 10.0.1.1/24 dev demo-bridge"
echo "  ip link set demo-bridge up"
echo "  ping 10.0.1.10  # nginx container"
echo "  ping 10.0.1.11  # python container"

echo -e "\n8. Container network namespaces:"
for container in ovs-demo-nginx ovs-demo-python; do
    pid=$(docker inspect -f '{{.State.Pid}}' $container 2>/dev/null || echo "not found")
    if [[ "$pid" != "not found" && "$pid" != "0" ]]; then
        echo "Container $container (PID: $pid):"
        nsenter -t $pid -n ip addr show eth1 2>/dev/null || echo "  eth1 interface not found"
    fi
done

echo -e "\nDemo running... Press Ctrl+C to stop and cleanup"

# Wait for user interrupt
wait $MANAGER_PID
