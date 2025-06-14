# Configuration Guide

The OVS Port Manager supports flexible configuration through environment variables, configuration files, and command-line arguments.

## Configuration Priority

Configuration is loaded in the following order (highest priority first):

1. Environment variables (prefixed with `OVS_PORT_MANAGER_`)
2. Configuration file
3. Default values

## Environment Variables

All configuration options can be set via environment variables by prefixing them with `OVS_PORT_MANAGER_` and using uppercase letters with underscores.

### Key Environment Variables

- `OVS_DB`: OVS database name (default: "Open_vSwitch")
- `OVS_PORT_MANAGER_OVS_SOCKET_PATH`: OVS database socket path
- `OVS_PORT_MANAGER_LOGGING_LEVEL`: Log level (debug, info, warn, error)
- `OVS_PORT_MANAGER_OVS_DEFAULT_BRIDGE`: Default bridge name
- `OVS_PORT_MANAGER_OVS_DEFAULT_INTERFACE`: Default interface name

## Configuration File

The application looks for configuration files in the following locations:

1. `/etc/ovs-port-manager/ovs-port-manager.yaml`
2. `$HOME/.ovs-port-manager/ovs-port-manager.yaml`
3. `./ovs-port-manager.yaml` (current directory)

### Example Configuration

```yaml
ovs:
  database_name: "Open_vSwitch"
  socket_path: "/var/run/openvswitch/db.sock"
  default_bridge: "ovs_bond0"
  default_interface: "bond0"

logging:
  level: "info"
  format: "json"

network:
  default_mtu: 1500
  enable_ipv6: false
```

## Docker Environment

When running in Docker, you can set environment variables:

```bash
docker run -d \
  --name ovs-port-manager \
  --network host \
  --privileged \
  -e OVS_DB=Custom_Database \
  -e OVS_PORT_MANAGER_LOGGING_LEVEL=debug \
  -e OVS_PORT_MANAGER_OVS_DEFAULT_BRIDGE=br0 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/run/openvswitch:/var/run/openvswitch \
  ghcr.io/appkins-org/ovs-port-manager:latest
```

## Configuration Validation

The application validates configuration on startup and will fail to start if:

- Required paths are not accessible
- Invalid log levels are specified
- Network configuration is invalid

## Advanced Configuration

### Custom OVS Database

To use a custom OVS database name:

```bash
export OVS_DB=MyCustomDatabase
# or
export OVS_PORT_MANAGER_OVS_DATABASE_NAME=MyCustomDatabase
```

### Custom Socket Paths

For non-standard OVS installations:

```yaml
ovs:
  socket_path: "/usr/local/var/run/openvswitch/db.sock"
docker:
  socket_path: "/var/run/docker.sock"
```

### JSON Logging

For structured logging in production:

```yaml
logging:
  level: "info"
  format: "json"
  structured: true
```

### Metrics and Health Checks

Enable monitoring endpoints:

```yaml
server:
  enable_metrics: true
  metrics_addr: ":8080"
  enable_health_check: true
  health_addr: ":8081"
```
