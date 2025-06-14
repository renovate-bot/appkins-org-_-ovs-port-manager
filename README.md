# OVS Port Manager

A Go application that automatically manages Open vSwitch (OVS) ports for Docker containers based on labels. This tool monitors Docker events and automatically adds/removes OVS ports when containers with the `ovs.ip_address` label are started or stopped.

## Features

- Monitors Docker containers for OVS-related labels
- Automatically creates and configures OVS ports for labeled containers
- Supports custom bridge, gateway, MTU, and MAC address configuration
- Cleans up OVS ports when containers stop
- Based on the `ovs-docker` utility patterns
- Uses the DigitalOcean go-openvswitch library

## Project Structure

This project follows the [Standard Go Project Layout](https://github.com/golang-standards/project-layout):

```
├── cmd/                        # Main applications
│   └── ovs-port-manager/      # Main application entry point
├── internal/                   # Private application code
│   ├── config/                # Configuration handling
│   ├── manager/               # Core manager logic
│   └── models/                # OVS database models (generated)
├── configs/                    # Configuration files
│   └── ovs-port-manager.yaml  # Default configuration
├── assets/                     # Static assets and data files
│   └── ovs-nb.ovsschema      # OVS database schema
├── build/                      # Build and packaging files
│   └── package/               # Container packaging
│       ├── Dockerfile         # Docker image definition
│       └── docker-compose.yml # Docker compose configuration
├── scripts/                    # Build and utility scripts
├── docs/                       # Documentation
└── generate.go                # Code generation directives
```

## Prerequisites

- Docker daemon running and accessible
- Open vSwitch installed and running
- Root privileges (required for network namespace operations)
- Go 1.24 or later

### Installing Open vSwitch

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install openvswitch-switch
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install openvswitch
# or
sudo yum install openvswitch
```

**macOS:**
```bash
brew install openvswitch
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/appkins-org/ovs-port-manager.git
cd ovs-port-manager
```

2. Build the application:
```bash
go build -o ovs-port-manager
```

3. Run with appropriate privileges:
```bash
sudo ./ovs-port-manager
```

## Docker Labels

The following Docker labels are supported:

### Required Labels

- `ovs.ip_address`: IP address to assign to the container interface (e.g., "192.168.1.100/24")

### Optional Labels

- `ovs.bridge`: OVS bridge name (defaults to "ovsbr0")
- `ovs.gateway`: Gateway IP address
- `ovs.mtu`: MTU for the interface
- `ovs.mac_address`: MAC address for the interface

## Usage Examples

### Basic Usage

Run a container with an OVS IP address:

```bash
docker run -d --label ovs.ip_address=192.168.1.100/24 nginx:latest
```

### Advanced Configuration

Run a container with full OVS configuration:

```bash
docker run -d \
  --label ovs.ip_address=192.168.1.100/24 \
  --label ovs.bridge=my-bridge \
  --label ovs.gateway=192.168.1.1 \
  --label ovs.mtu=1500 \
  --label ovs.mac_address=02:42:ac:11:00:02 \
  nginx:latest
```

### Docker Compose Example

```yaml
version: '3.8'
services:
  web:
    image: nginx:latest
    labels:
      - "ovs.ip_address=192.168.1.100/24"
      - "ovs.bridge=web-bridge"
      - "ovs.gateway=192.168.1.1"
  
  app:
    image: python:3.9
    labels:
      - "ovs.ip_address=192.168.1.101/24"
      - "ovs.bridge=web-bridge"
      - "ovs.gateway=192.168.1.1"
    command: python -m http.server 8000
```

## Architecture

The application follows the `ovs-docker` utility pattern:

1. **Monitor Docker Events**: Listens for container start/stop events
2. **Extract Configuration**: Reads OVS-related labels from containers
3. **Create veth Pair**: Creates a virtual ethernet pair for each container
4. **Add to Bridge**: Adds the bridge-side interface to the specified OVS bridge
5. **Configure Container Interface**: Moves the container-side interface to the container's network namespace and configures IP, gateway, MTU, etc.
6. **Cleanup**: Removes OVS ports and veth pairs when containers stop

## Configuration

The application uses the following default values:

- Default bridge: `ovsbr0`
- Default container interface name: `eth1`
- Log level: `info`

## Logging

The application uses structured logging (logr) with the following levels:
- `V(2)`: Detailed operation logs (debug level)
- `Info`: General operation logs
- `Error`: Error messages

To enable debug logging, set the verbosity level when creating the logger in your environment.

## Security Considerations

- The application requires root privileges to manipulate network namespaces
- Docker socket access is required to monitor container events
- OVS operations typically require sudo access

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the application is running with root privileges
2. **OVS Bridge Not Found**: Make sure the specified bridge exists or let the application create the default bridge
3. **Docker Connection Failed**: Verify Docker daemon is running and accessible

### Debug Mode

To enable verbose logging, configure the logger verbosity level when creating the logr logger:

```go
// Example: Create a logger with debug level verbosity
zapLogger, err := zap.NewProduction()
if err != nil {
    panic(err)
}
logger := zapr.NewLogger(zapLogger).V(2) // V(2) enables debug-level logs
```

### Manual Cleanup

If containers are not cleaned up properly, you can manually remove OVS ports:

```bash
# List all OVS ports
sudo ovs-vsctl show

# Remove a specific port
sudo ovs-vsctl del-port bridge-name port-name

# Remove all ports for a container
sudo ovs-vsctl --columns=name --format=csv --no-headings --data=bare \
  find interface external_ids:container_id=CONTAINER_ID | \
  xargs -I {} sudo ovs-vsctl del-port {}
```

## Development

### Building

```bash
go build -o ovs-port-manager
```

### Running Tests

```bash
go test ./...
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [Open vSwitch Documentation](https://docs.openvswitch.org/)
- [ovs-docker utility](https://github.com/openvswitch/ovs/blob/main/utilities/ovs-docker)
- [DigitalOcean go-openvswitch library](https://github.com/digitalocean/go-openvswitch)
- [Docker API Documentation](https://docs.docker.com/engine/api/)

## Migration to libovsdb

This project has been migrated from using direct `ovs-vsctl` command execution to using the [libovsdb](https://github.com/ovn-org/libovsdb) library for all OVS database operations. This provides several advantages:

### Benefits of libovsdb Migration

1. **Better Performance**: Direct database operations instead of spawning processes
2. **Type Safety**: Strongly typed database schema models
3. **Transaction Support**: Atomic operations with proper rollback
4. **Event Monitoring**: Real-time database change notifications
5. **Error Handling**: Better error reporting and handling

### Key Changes

#### Database Schema Models
The project now defines Go structs that map to OVS database tables:

```go
type Bridge struct {
    UUID         string            `ovsdb:"_uuid"`
    Name         string            `ovsdb:"name"`
    Ports        []string          `ovsdb:"ports"`
    ExternalIDs  map[string]string `ovsdb:"external_ids"`
    OtherConfig  map[string]string `ovsdb:"other_config"`
}

type Port struct {
    UUID        string            `ovsdb:"_uuid"`
    Name        string            `ovsdb:"name"`
    Interfaces  []string          `ovsdb:"interfaces"`
    ExternalIDs map[string]string `ovsdb:"external_ids"`
}

type Interface struct {
    UUID        string            `ovsdb:"_uuid"`
    Name        string            `ovsdb:"name"`
    Type        string            `ovsdb:"type"`
    ExternalIDs map[string]string `ovsdb:"external_ids"`
}
```

#### Database Operations
- **Bridge Creation**: Uses `client.Create()` with proper Bridge model
- **Port Management**: Creates Port and Interface models with relationships
- **Query Operations**: Uses `WhereCache()` for efficient cache-based queries
- **Cleanup Operations**: Proper cascading deletes with transaction support

#### Connection Management
- Direct connection to OVS database socket (`unix:/var/run/openvswitch/db.sock`)
- Automatic reconnection and error handling
- Proper connection lifecycle management

### Dependencies
- Added: `github.com/ovn-org/libovsdb v0.7.0`
- Removed dependency on: Direct `ovs-vsctl` command execution

## Migration to Netlink

This project has been enhanced to use the [netlink](https://github.com/vishvananda/netlink) library for all network interface operations instead of executing `ip` commands directly. This provides significant benefits:

### Benefits of Netlink Migration

1. **Better Performance**: Direct kernel netlink operations instead of spawning processes
2. **Type Safety**: Strongly typed network configuration operations
3. **Error Handling**: More precise error reporting and handling
4. **Cross-Platform**: Better compatibility across different Linux distributions
5. **Atomic Operations**: Better transaction support for network configuration

### Key Network Operations Migrated

#### Veth Pair Management
- **Before**: `ip link add veth_l type veth peer name veth_c`
- **After**: `netlink.LinkAdd(&netlink.Veth{...})`

#### Interface Configuration
- **Before**: Multiple `ip` commands for each operation
- **After**: Direct netlink calls for each operation:
  - `netlink.LinkSetUp()` - Bring interface up
  - `netlink.LinkSetNsPid()` - Move to namespace
  - `netlink.LinkSetName()` - Rename interface
  - `netlink.LinkSetHardwareAddr()` - Set MAC address
  - `netlink.LinkSetMTU()` - Set MTU
  - `netlink.AddrAdd()` - Add IP address
  - `netlink.RouteAdd()` - Add routes

#### Network Namespace Operations
- **Before**: `ip netns exec` commands
- **After**: Direct namespace handle operations using `netns.GetFromPid()` and `netlink.NewHandleAt()`

### Implementation Details

#### New Helper Functions
```go
func (m *OVSPortManager) createVethPair(portName string) error
func (m *OVSPortManager) setLinkUp(interfaceName string) error
func (m *OVSPortManager) moveLinkToNetns(interfaceName string, pid int) error
func (m *OVSPortManager) configureInterfaceInNetns(pid int, oldName, newName, ipAddr, macAddr, mtu, gateway string) error
func (m *OVSPortManager) deleteLinkByName(interfaceName string) error
```

#### Replaced Operations
| Old IP Command | New Netlink Operation |
|---|---|
| `ip link add ... type veth peer name ...` | `netlink.LinkAdd(&netlink.Veth{...})` |
| `ip link set ... up` | `netlink.LinkSetUp(link)` |
| `ip link set ... netns ...` | `netlink.LinkSetNsPid(link, pid)` |
| `ip link set dev ... name ...` | `netlink.LinkSetName(link, name)` |
| `ip addr add ... dev ...` | `netlink.AddrAdd(link, addr)` |
| `ip link set dev ... address ...` | `netlink.LinkSetHardwareAddr(link, mac)` |
| `ip link set dev ... mtu ...` | `netlink.LinkSetMTU(link, mtu)` |
| `ip route add default via ...` | `netlink.RouteAdd(&netlink.Route{...})` |
| `ip link delete ...` | `netlink.LinkDel(link)` |

### Dependencies Added
- `github.com/vishvananda/netlink v1.3.1` - Main netlink library
- `github.com/vishvananda/netns v0.0.5` - Network namespace utilities

### Backward Compatibility
The `runCommand` method is still available for any non-network operations that might need shell command execution.

## Docker Image

### Multi-Platform Support

Pre-built Docker images are available for multiple architectures:

- `linux/amd64` (x86_64)
- `linux/arm64` (ARM64/AArch64)

### Using the Docker Image

Pull and run the latest image:

```bash
# Pull the latest image
docker pull ghcr.io/appkins-org/ovs-port-manager:latest

# Run the container with host networking and Docker socket access
docker run -d \
  --name ovs-port-manager \
  --network host \
  --privileged \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/run/openvswitch:/var/run/openvswitch \
  ghcr.io/appkins-org/ovs-port-manager:latest
```

### Building Locally

To build the multi-platform image locally:

```bash
# Build for current platform
docker build -t ovs-port-manager .

# Build for multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t ovs-port-manager .
```

### Available Tags

- `latest`: Latest stable release
- `main`: Latest from main branch
- `develop`: Latest from develop branch
- `v*.*.*`: Specific version releases

## Local Installation
