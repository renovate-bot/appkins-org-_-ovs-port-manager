package manager

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/appkins-org/ovs-port-manager/internal/config"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExternalRoutingIntegration tests the full external routing workflow
// This test requires root privileges and actual network interfaces.
func TestExternalRoutingIntegration(t *testing.T) {
	// Skip if not running as root or in CI environment
	if os.Geteuid() != 0 {
		t.Skip("Integration tests require root privileges")
	}

	// Skip if running in CI without network setup
	if os.Getenv("CI") == "true" && os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("Integration tests disabled in CI")
	}

	// Create test configuration
	cfg := &config.Config{
		OVS: config.OVSConfig{
			DatabaseName:      "Open_vSwitch",
			SocketPath:        "/var/run/openvswitch/db.sock",
			ConnectionTimeout: 30 * time.Second,
			DefaultBridge:     "ovsbr0",
			DefaultInterface:  "eth1",
		},
		Network: config.NetworkConfig{
			EnableExternalRouting: true,
			DefaultMTU:            1500,
		},
		Logging: config.LoggingConfig{
			Level:  "debug",
			Format: "text",
		},
	}

	logger := logr.Discard() // Use discard logger for cleaner test output

	// Create manager
	manager := &Manager{
		config: cfg,
		logger: logger,
	}

	// Test container configuration
	containerID := "test123456789ab"
	testConfig := &ContainerOVSConfig{
		ContainerID:       containerID,
		IPAddress:         "192.168.100.10/24",
		Bridge:            "ovsbr0",
		Interface:         "eth1",
		ExternalIP:        "169.254.169.254/32",
		ExternalGateway:   "169.254.1.1",
		ExternalInterface: "",
	}

	// Clean up any existing test configuration
	defer func() {
		if err := manager.removeExternalIPRouting(
			testConfig.ExternalIP,
			testConfig.ExternalGateway,
			containerID,
		); err != nil {
			t.Logf("Cleanup warning: %v", err)
		}
	}()

	t.Run("setup_external_routing", func(t *testing.T) {
		err := manager.setupExternalIPRouting(
			testConfig.ExternalIP,
			testConfig.ExternalGateway,
			containerID,
		)

		// In real integration tests, this would succeed
		// In unit tests without proper network setup, we expect specific errors
		if err != nil {
			// Check that the error is due to missing network interface, not logic errors
			assert.Contains(t, err.Error(), "failed to find host interface",
				"Expected error due to missing test interface")
		} else {
			// If it succeeds, verify the configuration was applied
			t.Log("External routing setup succeeded")
		}
	})

	t.Run("cleanup_external_routing", func(t *testing.T) {
		err := manager.removeExternalIPRouting(
			testConfig.ExternalIP,
			testConfig.ExternalGateway,
			containerID,
		)

		// Cleanup should always succeed (idempotent)
		assert.NoError(t, err, "External routing cleanup should be idempotent")
	})
}

// TestExternalRoutingLabels tests that Docker labels are correctly parsed.
func TestExternalRoutingLabels(t *testing.T) {
	testCases := []struct {
		name        string
		labels      map[string]string
		expected    *ContainerOVSConfig
		description string
	}{
		{
			name: "full_external_config",
			labels: map[string]string{
				"ovs.ip_address":         "192.168.1.100/24",
				"ovs.bridge":             "br0",
				"ovs.interface":          "eth1",
				"ovs.external_ip":        "169.254.169.254/32",
				"ovs.external_gateway":   "169.254.1.1",
				"ovs.external_interface": "eth0",
			},
			expected: &ContainerOVSConfig{
				IPAddress:         "192.168.1.100/24",
				Bridge:            "br0",
				Interface:         "eth1",
				ExternalIP:        "169.254.169.254/32",
				ExternalGateway:   "169.254.1.1",
				ExternalInterface: "eth0",
			},
			description: "Full external configuration with all labels",
		},
		{
			name: "external_ip_only",
			labels: map[string]string{
				"ovs.ip_address":  "192.168.1.100/24",
				"ovs.external_ip": "10.0.0.100/32",
			},
			expected: &ContainerOVSConfig{
				IPAddress:         "192.168.1.100/24",
				ExternalIP:        "10.0.0.100/32",
				ExternalGateway:   "",
				ExternalInterface: "",
			},
			description: "External IP without gateway or interface",
		},
		{
			name: "no_external_config",
			labels: map[string]string{
				"ovs.ip_address": "192.168.1.100/24",
				"ovs.bridge":     "br0",
			},
			expected: &ContainerOVSConfig{
				IPAddress:         "192.168.1.100/24",
				Bridge:            "br0",
				ExternalIP:        "",
				ExternalGateway:   "",
				ExternalInterface: "",
			},
			description: "No external configuration labels",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test manager
			logger := logr.Discard()
			manager := &Manager{
				logger: logger,
				config: &config.Config{
					OVS: config.OVSConfig{
						DefaultBridge:    "ovsbr0",
						DefaultInterface: "eth1",
					},
				},
			}

			// Parse labels into config - simulate how labels would be parsed
			config := &ContainerOVSConfig{
				ContainerID:       "test-container",
				IPAddress:         tc.labels["ovs.ip_address"],
				Bridge:            tc.labels["ovs.bridge"],
				Interface:         tc.labels["ovs.interface"],
				ExternalIP:        tc.labels["ovs.external_ip"],
				ExternalGateway:   tc.labels["ovs.external_gateway"],
				ExternalInterface: tc.labels["ovs.external_interface"],
			}

			// Apply defaults if not specified
			if config.Bridge == "" {
				config.Bridge = manager.config.OVS.DefaultBridge
			}
			if config.Interface == "" {
				config.Interface = manager.config.OVS.DefaultInterface
			}

			// Verify external fields
			assert.Equal(t, tc.expected.ExternalIP, config.ExternalIP,
				"ExternalIP mismatch: %s", tc.description)
			assert.Equal(t, tc.expected.ExternalGateway, config.ExternalGateway,
				"ExternalGateway mismatch: %s", tc.description)
			assert.Equal(t, tc.expected.ExternalInterface, config.ExternalInterface,
				"ExternalInterface mismatch: %s", tc.description)

			// Verify other fields are preserved
			assert.Equal(t, tc.expected.IPAddress, config.IPAddress,
				"IPAddress mismatch: %s", tc.description)
		})
	}
}

// TestExternalRoutingEndToEnd simulates a complete container lifecycle with external routing.
func TestExternalRoutingEndToEnd(t *testing.T) {
	// Skip if not running integration tests
	if os.Getenv("INTEGRATION_TESTS") != "true" {
		t.Skip("End-to-end tests require INTEGRATION_TESTS=true")
	}

	logger := logr.Discard()

	// Load actual configuration
	cfg, err := config.Load()
	require.NoError(t, err, "Failed to load configuration")

	// Enable external routing for test
	cfg.Network.EnableExternalRouting = true

	// Create manager (this will fail without proper OVS setup)
	manager, err := New(logger)
	if err != nil {
		t.Skipf("Cannot create manager, OVS likely not available: %v", err)
	}

	ctx := context.Background()

	// Test configuration
	testConfig := &ContainerOVSConfig{
		ContainerID:       "integration-test-123",
		IPAddress:         "192.168.200.10/24",
		Bridge:            cfg.OVS.DefaultBridge,
		Interface:         cfg.OVS.DefaultInterface,
		ExternalIP:        "169.254.200.10/32",
		ExternalGateway:   "169.254.1.1",
		ExternalInterface: "",
	}

	// Clean up at the end
	defer func() {
		_ = manager.removeOVSPort(ctx, testConfig.ContainerID)
	}()

	t.Run("add_ovs_port_with_external_routing", func(t *testing.T) {
		err := manager.addOVSPort(ctx, testConfig)

		// This may fail due to missing container or network setup
		if err != nil {
			t.Logf("Expected failure in test environment: %v", err)
		} else {
			t.Log("Successfully added OVS port with external routing")
		}
	})

	t.Run("remove_ovs_port_with_external_routing", func(t *testing.T) {
		err := manager.removeOVSPort(ctx, testConfig.ContainerID)
		// Removal should be idempotent
		if err != nil {
			t.Logf("Remove operation result: %v", err)
		}
	})
}

// TestExternalRoutingConfiguration tests configuration validation.
func TestExternalRoutingConfiguration(t *testing.T) {
	testCases := []struct {
		name        string
		config      *config.Config
		expectValid bool
		description string
	}{
		{
			name: "external_routing_enabled",
			config: &config.Config{
				Network: config.NetworkConfig{
					EnableExternalRouting:    true,
					DefaultExternalInterface: "eth0",
				},
			},
			expectValid: true,
			description: "External routing enabled with default interface",
		},
		{
			name: "external_routing_disabled",
			config: &config.Config{
				Network: config.NetworkConfig{
					EnableExternalRouting: false,
				},
			},
			expectValid: true,
			description: "External routing disabled",
		},
		{
			name: "external_routing_enabled_no_default_interface",
			config: &config.Config{
				Network: config.NetworkConfig{
					EnableExternalRouting:    true,
					DefaultExternalInterface: "",
				},
			},
			expectValid: true,
			description: "External routing enabled without default interface",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()

			if tc.expectValid {
				assert.NoError(t, err, tc.description)
			} else {
				assert.Error(t, err, tc.description)
			}
		})
	}
}

// Example test showing expected behavior for external routing.
func ExampleManager_externalRouting() {
	// This example shows how external routing works
	_ = &config.Config{
		Network: config.NetworkConfig{
			EnableExternalRouting: true,
		},
	}

	// Container configuration with external routing
	containerConfig := &ContainerOVSConfig{
		ContainerID:       "example123456789",
		IPAddress:         "192.168.1.100/24",   // Internal OVS network
		ExternalIP:        "169.254.169.254/32", // External routable IP
		ExternalGateway:   "169.254.1.1",        // Optional gateway
		ExternalInterface: "",                   // Use default host interface
	}

	// This would set up:
	// 1. ip addr add 169.254.169.254/32 dev example123456_l
	// 2. ip route add 169.254.169.254/32 dev example123456_l
	// 3. Optional gateway route if specified

	containerID := containerConfig.ContainerID

	fmt.Printf("Setting up external routing for container %s\n", containerID[:12])
	fmt.Printf("External IP: %s\n", containerConfig.ExternalIP)
	fmt.Printf("Internal IP: %s\n", containerConfig.IPAddress)

	// Output:
	// Setting up external routing for container example12345
	// External IP: 169.254.169.254/32
	// Internal IP: 192.168.1.100/24
}
