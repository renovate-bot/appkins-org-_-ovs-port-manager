# OVS Port Manager Tests

This directory contains comprehensive Go tests for the OVS Port Manager functionality.

## Test Files

### Core Test Files

1. **`manager_test.go`** - Original tests for port name generation and OVS Docker mirroring behavior
2. **`mac_test.go`** - Tests for deterministic MAC address generation from IP addresses
3. **`config_test.go`** - Tests for container OVS configuration extraction and validation
4. **`network_test.go`** - Extended tests for network interface naming and limits
5. **`vlan_test.go`** - Tests for VLAN ID validation and parsing
6. **`uuid_test.go`** - Tests for UUID generation consistency and format
7. **`comprehensive_test.go`** - High-level integration tests and benchmarks

## Test Categories

### Unit Tests
- **MAC Address Generation**: Tests deterministic MAC generation from IP addresses
- **Port Name Generation**: Tests container ID to port name conversion
- **Configuration Parsing**: Tests Docker label parsing into OVS configuration
- **VLAN Validation**: Tests VLAN ID range validation (1-4094)
- **UUID Generation**: Tests deterministic UUID generation for OVSDB

### Integration Tests
- **Interface Naming**: Tests that generated names don't exceed Linux kernel limits
- **OVS Compatibility**: Tests that functionality matches ovs-docker.sh behavior
- **Error Handling**: Tests proper error handling for invalid inputs

### Performance Tests
- **Benchmarks**: Performance tests for critical path functions
- **Memory Usage**: Tests for memory efficiency

## Running Tests

### All Tests
```bash
go test ./internal/manager -v
```

### Specific Test Categories
```bash
# MAC generation tests
go test ./internal/manager -v -run TestGenerateDeterministicMAC

# Network interface tests  
go test ./internal/manager -v -run TestGeneratePortName

# VLAN tests
go test ./internal/manager -v -run TestVLAN

# UUID tests
go test ./internal/manager -v -run TestUUID
```

### With Coverage
```bash
go test ./internal/manager -cover
```

### With Race Detection
```bash
go test ./internal/manager -race
```

### Benchmarks
```bash
go test ./internal/manager -bench=.
```

## Test Requirements

### Key Validations
1. **Interface Name Limits**: All generated interface names must be ≤ 15 characters (Linux IFNAMSIZ-1)
2. **MAC Address Format**: Generated MACs must have locally administered bit set and multicast bit clear
3. **UUID Consistency**: Same input must always generate the same UUID
4. **VLAN Range**: Valid VLAN IDs are 1-4094 (0 and 4095 are reserved)
5. **OVS Compatibility**: Behavior must match ovs-docker.sh patterns

### Test Data
- Uses realistic container IDs (64-character hex strings)
- Tests IPv4 and IPv6 addresses
- Covers edge cases and boundary conditions
- Validates error handling paths

## Expected Behavior

### Port Naming
- Container ID `1322aba3640c7f8a...` → Port name `1322aba3640c`
- Host-side veth: `1322aba3640c_l` (14 chars, under 15 limit)
- Container-side veth: `1322aba3640c_c` (14 chars, under 15 limit)

### MAC Generation
- IP `192.168.1.1` → Deterministic MAC with locally administered bit set
- Same IP always generates same MAC
- Different IPs generate different MACs

### Configuration
- Docker labels `ovs.ip_address`, `ovs.bridge`, etc. → ContainerOVSConfig struct
- Default bridge: `ovsbr0`
- Default interface: `eth1`

## Debugging

### Running Individual Tests
```bash
go test ./internal/manager -v -run TestSpecificFunction
```

### Verbose Output
```bash
go test ./internal/manager -v -args -test.v
```

### Test with Debug Logging
Tests use `logr.Discard()` to suppress logs. For debugging, replace with a real logger.
