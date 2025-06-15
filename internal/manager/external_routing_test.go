package manager

import (
	"net"
	"testing"

	"github.com/appkins-org/ovs-port-manager/internal/config"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// MockNetlinkHandle is a mock implementation of netlink operations for testing.
type MockNetlinkHandle struct {
	links     map[string]*netlink.Dummy // Use dummy interfaces for testing
	addresses map[string][]netlink.Addr
	routes    []netlink.Route
	errors    map[string]error // Method name -> error to return
}

func NewMockNetlinkHandle() *MockNetlinkHandle {
	return &MockNetlinkHandle{
		links:     make(map[string]*netlink.Dummy),
		addresses: make(map[string][]netlink.Addr),
		routes:    make([]netlink.Route, 0),
		errors:    make(map[string]error),
	}
}

func (m *MockNetlinkHandle) SetError(method string, err error) {
	m.errors[method] = err
}

func (m *MockNetlinkHandle) AddLink(name string) {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:  name,
			Index: len(m.links) + 1,
		},
	}
	m.links[name] = dummy
}

func (m *MockNetlinkHandle) GetRoutes() []netlink.Route {
	return m.routes
}

// TestExternalRoutingSetup tests the external routing setup functionality.
func TestExternalRoutingSetup(t *testing.T) {
	tests := []struct {
		name        string
		externalIP  string
		gateway     string
		containerID string
		expectError bool
		description string
	}{
		{
			name:        "IPv4_with_gateway",
			externalIP:  "169.254.169.254/32",
			gateway:     "169.254.1.1",
			containerID: "1234567890ab",
			expectError: false,
			description: "Standard IPv4 external routing with gateway",
		},
		{
			name:        "IPv4_no_gateway",
			externalIP:  "192.168.100.50/32",
			gateway:     "",
			containerID: "abcdef123456",
			expectError: false,
			description: "IPv4 external routing without gateway",
		},
		{
			name:        "IPv6_external_ip",
			externalIP:  "2001:db8::1/128",
			gateway:     "2001:db8::100",
			containerID: "fedcba654321",
			expectError: false,
			description: "IPv6 external routing",
		},
		{
			name:        "invalid_ip",
			externalIP:  "invalid-ip",
			gateway:     "",
			containerID: "1111222233334",
			expectError: true,
			description: "Should fail with invalid IP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test manager
			cfg := &config.Config{
				Network: config.NetworkConfig{
					EnableExternalRouting: true,
				},
			}

			logger := logr.Discard()
			manager := &Manager{
				config: cfg,
				logger: logger,
			}

			// Test setup
			err := manager.setupExternalIPRouting(tt.externalIP, tt.gateway, tt.containerID)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

// TestExternalRoutingCleanup tests the external routing cleanup functionality.
func TestExternalRoutingCleanup(t *testing.T) {
	tests := []struct {
		name        string
		externalIP  string
		gateway     string
		containerID string
		description string
	}{
		{
			name:        "cleanup_ipv4",
			externalIP:  "169.254.169.254/32",
			gateway:     "169.254.1.1",
			containerID: "1234567890ab",
			description: "Clean up IPv4 external routing",
		},
		{
			name:        "cleanup_no_gateway",
			externalIP:  "192.168.100.50/32",
			gateway:     "",
			containerID: "abcdef123456",
			description: "Clean up without gateway",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Network: config.NetworkConfig{
					EnableExternalRouting: true,
				},
			}

			logger := logr.Discard()
			manager := &Manager{
				config: cfg,
				logger: logger,
			}

			// Cleanup should not fail even if nothing was set up
			err := manager.removeExternalIPRouting(tt.externalIP, tt.gateway, tt.containerID)
			assert.NoError(t, err, tt.description)
		})
	}
}

// TestAddExternalRoute tests the addExternalRoute function.
func TestAddExternalRoute(t *testing.T) {
	tests := []struct {
		name          string
		externalIP    string
		hostInterface string
		expectError   bool
		description   string
	}{
		{
			name:          "valid_ipv4",
			externalIP:    "169.254.169.254",
			hostInterface: "test_l",
			expectError:   false,
			description:   "Valid IPv4 address",
		},
		{
			name:          "valid_ipv6",
			externalIP:    "2001:db8::1",
			hostInterface: "test_l",
			expectError:   false,
			description:   "Valid IPv6 address",
		},
		{
			name:          "invalid_ip",
			externalIP:    "not-an-ip",
			hostInterface: "test_l",
			expectError:   true,
			description:   "Invalid IP address should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logr.Discard()
			manager := &Manager{
				logger: logger,
			}

			err := manager.addExternalRoute(tt.externalIP, tt.hostInterface)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				// Since we can't create actual interfaces in unit tests,
				// we expect this to fail due to missing interface,
				// but the IP parsing should succeed
				if err != nil {
					assert.Contains(t, err.Error(), "failed to find host interface", tt.description)
				}
			}
		})
	}
}

// TestRemoveExternalRoute tests the removeExternalRoute function.
func TestRemoveExternalRoute(t *testing.T) {
	tests := []struct {
		name          string
		externalIP    string
		hostInterface string
		description   string
	}{
		{
			name:          "remove_ipv4",
			externalIP:    "169.254.169.254",
			hostInterface: "test_l",
			description:   "Remove IPv4 route",
		},
		{
			name:          "remove_ipv6",
			externalIP:    "2001:db8::1",
			hostInterface: "test_l",
			description:   "Remove IPv6 route",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logr.Discard()
			manager := &Manager{
				logger: logger,
			}

			// Should not fail even if route doesn't exist
			err := manager.removeExternalRoute(tt.externalIP, tt.hostInterface)
			// We expect no error or a "not found" type error
			if err != nil {
				assert.Contains(t, err.Error(), "failed to find host interface", tt.description)
			}
		})
	}
}

// TestPortNameGeneration tests that the port name generation works correctly.
func TestPortNameGeneration(t *testing.T) {
	logger := logr.Discard()
	manager := &Manager{
		logger: logger,
	}

	tests := []struct {
		name        string
		containerID string
		expected    string
	}{
		{
			name:        "standard_container_id",
			containerID: "1234567890abcdef",
			expected:    "1234567890ab",
		},
		{
			name:        "short_container_id",
			containerID: "12345",
			expected:    "12345",
		},
		{
			name:        "long_container_id",
			containerID: "1234567890abcdef1234567890abcdef12345678",
			expected:    "1234567890ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.generatePortName(tt.containerID)
			assert.Equal(t, tt.expected, result)

			// Verify host-side and container-side names are within limits
			hostSide := result + "_l"
			containerSide := result + "_c"

			assert.LessOrEqual(t, len(hostSide), InterfaceNameLimit,
				"Host-side interface name too long: %s", hostSide)
			assert.LessOrEqual(t, len(containerSide), InterfaceNameLimit,
				"Container-side interface name too long: %s", containerSide)
		})
	}
}

// TestExternalIPParsing tests IP address parsing for external routing.
func TestExternalIPParsing(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectIPv4  bool
		expectIPv6  bool
		expectError bool
	}{
		{
			name:        "ipv4_with_cidr",
			input:       "169.254.169.254/32",
			expectIPv4:  true,
			expectIPv6:  false,
			expectError: false,
		},
		{
			name:        "ipv4_without_cidr",
			input:       "192.168.1.100",
			expectIPv4:  true,
			expectIPv6:  false,
			expectError: false,
		},
		{
			name:        "ipv6_with_cidr",
			input:       "2001:db8::1/128",
			expectIPv4:  false,
			expectIPv6:  true,
			expectError: false,
		},
		{
			name:        "ipv6_without_cidr",
			input:       "2001:db8::1",
			expectIPv4:  false,
			expectIPv6:  true,
			expectError: false,
		},
		{
			name:        "invalid_ip",
			input:       "not-an-ip",
			expectIPv4:  false,
			expectIPv6:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract IP from CIDR if present
			ipStr := tt.input
			if _, _, err := net.ParseCIDR(tt.input); err == nil {
				ip, _, _ := net.ParseCIDR(tt.input)
				ipStr = ip.String()
			}

			ip := net.ParseIP(ipStr)

			if tt.expectError {
				assert.Nil(t, ip, "Expected parsing to fail for: %s", tt.input)
			} else {
				require.NotNil(t, ip, "Expected valid IP for: %s", tt.input)

				if tt.expectIPv4 {
					assert.NotNil(t, ip.To4(), "Expected IPv4 for: %s", tt.input)
				}

				if tt.expectIPv6 {
					assert.Nil(t, ip.To4(), "Expected IPv6 (not IPv4) for: %s", tt.input)
				}
			}
		})
	}
}

// TestContainerOVSConfigExternalFields tests the external routing fields in ContainerOVSConfig.
func TestContainerOVSConfigExternalFields(t *testing.T) {
	config := &ContainerOVSConfig{
		ContainerID:       "1234567890ab",
		IPAddress:         "192.168.1.100/24",
		Bridge:            "ovsbr0",
		ExternalIP:        "169.254.169.254/32",
		ExternalGateway:   "169.254.1.1",
		ExternalInterface: "eth0",
	}

	// Verify all external fields are set
	assert.NotEmpty(t, config.ExternalIP, "ExternalIP should be set")
	assert.NotEmpty(t, config.ExternalGateway, "ExternalGateway should be set")
	assert.NotEmpty(t, config.ExternalInterface, "ExternalInterface should be set")

	// Verify external IP is different from internal IP
	assert.NotEqual(t, config.IPAddress, config.ExternalIP,
		"External IP should be different from internal IP")
}

// BenchmarkExternalRouting benchmarks the external routing operations.
func BenchmarkExternalRouting(b *testing.B) {
	logger := logr.Discard()
	manager := &Manager{
		logger: logger,
		config: &config.Config{
			Network: config.NetworkConfig{
				EnableExternalRouting: true,
			},
		},
	}

	containerID := "1234567890abcdef"
	externalIP := "169.254.169.254/32"
	gateway := "169.254.1.1"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// These will fail due to missing interfaces, but we're measuring
		// the parsing and validation overhead
		_ = manager.setupExternalIPRouting(externalIP, gateway, containerID)
		_ = manager.removeExternalIPRouting(externalIP, gateway, containerID)
	}
}
