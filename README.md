# OVS Port Manager

A Go application that automatically manages Open vSwitch (OVS) ports for Docker containers based on labels. This tool monitors Docker events and automatically adds/removes OVS ports when containers with the `ovs.ip_address` label are started or stopped.

## Features

- Monitors Docker containers for OVS-related labels
- Automatically creates and configures OVS ports for labeled containers
- Supports custom bridge, gateway, MTU, and MAC address configuration
- Cleans up OVS ports when containers stop
- Based on the `ovs-docker` utility patterns
- Uses the DigitalOcean go-openvswitch library

## Prerequisites

- Docker daemon running and accessible
- Open vSwitch installed and running
- Root privileges (required for network namespace operations)
- Go 1.21 or later

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

The application uses structured logging (logrus) with the following levels:
- `debug`: Detailed command execution logs
- `info`: General operation logs
- `warn`: Warning messages
- `error`: Error messages

To enable debug logging, modify the log level in the source code or use environment variables.

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

To enable verbose logging, modify the log level in `main.go`:

```go
logger.SetLevel(logrus.DebugLevel)
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
