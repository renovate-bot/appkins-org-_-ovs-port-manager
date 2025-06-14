# OVS-Docker Mirroring Implementation

This document describes how the OVS Port Manager now mirrors the exact behavior of the official `ovs-docker` script from the Open vSwitch project.

## Overview

The OVS Port Manager has been refactored to exactly replicate the workflow of the `ovs-docker add-port` and `del-port` commands, ensuring full compatibility with existing OVS/Docker integrations.

## Key Components

### 1. Port Addition Workflow (`addPortToBridge`)

The `addPortToBridge` function mirrors the `ovs-docker add-port` command exactly:

```bash
# ovs-docker equivalent workflow:
# 1. Check if port already exists for container/interface
# 2. Ensure bridge exists (ovs-vsctl br-exists || ovs-vsctl add-br)
# 3. Create veth pair: ip link add "${PORTNAME}_l" type veth peer name "${PORTNAME}_c"
# 4. Add host side to bridge: ovs-vsctl --may-exist add-port "$BRIDGE" "${PORTNAME}_l"
# 5. Set external_ids: ovs-vsctl set interface "${PORTNAME}_l" external_ids:container_id="$CONTAINER" external_ids:container_iface="$INTERFACE"
# 6. Bring up host side: ip link set "${PORTNAME}_l" up
```

**Implementation Features:**
- **Port naming**: Uses container ID prefix (first 12 chars) to ensure unique, manageable names
- **Veth pair creation**: Creates `{portname}_l` (host side) and `{portname}_c` (container side)
- **External IDs**: Sets `container_id` and `container_iface` for port discovery
- **Error handling**: Complete rollback on any failure step
- **Bridge management**: Automatic bridge creation if it doesn't exist

### 2. Container Interface Configuration (`configureContainerInterface`)

Mirrors the container-side configuration from `ovs-docker`:

```bash
# ovs-docker container configuration:
# 1. Move container side to container: ip link set "${PORTNAME}_c" netns "$PID"
# 2. Rename interface: ip netns exec "$PID" ip link set dev "${PORTNAME}_c" name "$INTERFACE"
# 3. Set interface up: ip netns exec "$PID" ip link set "$INTERFACE" up  
# 4. Set MTU: ip netns exec "$PID" ip link set dev "$INTERFACE" mtu "$MTU"
# 5. Add IP: ip netns exec "$PID" ip addr add "$ADDRESS" dev "$INTERFACE"
# 6. Set MAC: ip netns exec "$PID" ip link set dev "$INTERFACE" address "$MACADDRESS"
# 7. Add gateway: ip netns exec "$PID" ip route add default via "$GATEWAY"
```

**Implementation Features:**
- **Namespace handling**: Creates temporary symlinks to container network namespaces
- **Interface renaming**: Renames from `{portname}_c` to target interface name
- **Network configuration**: Supports IP, MAC, MTU, and gateway configuration
- **Error handling**: Proper cleanup and error reporting

### 3. Port Removal Workflow (`removeOVSPort`)

Mirrors `ovs-docker del-port` and `del-ports`:

```bash
# ovs-docker removal workflow:
# 1. Find ports by external_ids: ovs-vsctl find interface external_ids:container_id="$CONTAINER"
# 2. Remove from OVS: ovs-vsctl --if-exists del-port "$PORT"
# 3. Delete veth pair: ip link delete "$PORT"
```

**Implementation Features:**
- **Port discovery**: Finds ports by `container_id` external_id (like ovs-docker)
- **Clean removal**: Removes from OVS database and deletes network interfaces
- **Batch operations**: Handles multiple ports per container

### 4. Port Name Generation

**Pattern**: `{container_id_prefix}_l` (host) and `{container_id_prefix}_c` (container)

```go
// Examples:
// Container ID: 1322aba3640c7f3e8b9c123456789abc
// Generated names: 1322aba3640c_l, 1322aba3640c_c
```

**Benefits:**
- **Kernel compatibility**: Stays under 15-character interface name limit
- **Container linking**: Direct correlation between port name and container
- **Management**: Easy to identify and manage ports by container

### 5. External IDs Strategy

Following ovs-docker exactly:

```bash
external_ids:container_id="<full_container_id>"
external_ids:container_iface="<interface_name>"
```

**Benefits:**
- **Discovery**: Enables finding ports by container and interface
- **Compatibility**: Matches ovs-docker external_ids pattern
- **Management**: Supports multi-interface containers

## Network Namespace Handling

### Temporary Namespace Links

The implementation creates temporary symbolic links to container network namespaces:

```bash
# Equivalent to ovs-docker's create_netns_link function
ln -s /proc/$PID/ns/net /var/run/netns/tmp-$PID
```

### Namespace Operations

All container-side operations are performed within the container's network namespace using the `netns` package, mirroring the `ip netns exec` commands from ovs-docker.

## Error Handling and Cleanup

### Atomic Operations

Each port addition is atomic - if any step fails, all previous steps are rolled back:

1. **Veth creation fails**: No cleanup needed
2. **Bridge addition fails**: Delete veth pair  
3. **External ID setting fails**: Remove from bridge + delete veth
4. **Link up fails**: Remove from bridge + delete veth
5. **Container config fails**: Remove from bridge + delete veth

### Graceful Degradation

- **Missing containers**: Skips operations gracefully
- **Network namespace issues**: Proper error reporting
- **OVS connectivity**: Retries and error handling

## Integration Points

### Docker Events

The manager listens for Docker container events and automatically:

- **Start events**: Add OVS ports for containers with OVS labels
- **Stop/Die events**: Remove OVS ports and clean up interfaces

### Configuration

Environment variables and configuration file support for:

- **OVS connection**: Database socket, SSL certificates
- **Default bridge**: Bridge name for containers without explicit bridge label  
- **Logging**: Log level and format configuration

## Testing

### Unit Tests

- **Port name generation**: Validates naming patterns and length limits
- **External IDs**: Verifies ovs-docker compatibility
- **Configuration parsing**: Tests environment and file-based config

### Integration Tests

Ready for integration testing with:
- Docker containers with OVS labels
- OVS bridge and database operations
- Network namespace operations
- Multi-arch container support

## Compatibility

### OVS Docker Script

The implementation is designed to be a drop-in replacement for environments using `ovs-docker`, providing:

- **Identical port naming**
- **Same external_ids patterns**  
- **Compatible network configuration**
- **Equivalent error handling**

### Container Runtimes

While optimized for Docker, the implementation can work with other container runtimes that provide:

- Container inspection (PID retrieval)
- Container lifecycle events
- Label/annotation support

## Performance Considerations

### Efficient Port Discovery

- Uses OVS database queries with external_ids for fast port lookup
- Avoids scanning all ports/interfaces
- Caches container information between operations

### Minimal Network Namespace Operations

- Creates temporary namespace links only when needed
- Performs all container-side configuration in single namespace entry
- Proper cleanup of temporary resources

## Future Enhancements

### Potential Improvements

1. **Health Checks**: Periodic verification of port states
2. **Metrics**: Prometheus metrics for monitoring
3. **Webhooks**: Admission controllers for Kubernetes integration
4. **VLAN Support**: Implementation of `ovs-docker set-vlan` equivalent

### Maintenance

The implementation follows the ovs-docker patterns closely, making it easy to:

- Track upstream ovs-docker changes
- Add new ovs-docker features
- Maintain compatibility with existing deployments
