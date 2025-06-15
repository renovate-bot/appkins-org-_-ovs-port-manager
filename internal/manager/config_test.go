package manager

import (
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/go-logr/logr"
)

func TestExtractOVSConfig(t *testing.T) {
	// Create a manager for testing
	m := &Manager{
		logger: logr.Discard(),
	}

	tests := []struct {
		name           string
		containerInfo  types.ContainerJSON
		expectedConfig *ContainerOVSConfig
		expectError    bool
	}{
		{
			name: "Complete OVS configuration",
			containerInfo: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   "test-container-123",
					Name: "/test-container",
				},
				Config: &container.Config{
					Labels: map[string]string{
						OVSIPAddressLabel:  "192.168.1.100/24",
						OVSBridgeLabel:     "ovs-test",
						OVSGatewayLabel:    "192.168.1.1",
						OVSMTULabel:        "1500",
						OVSMACAddressLabel: "02:42:ac:11:00:02",
						OVSVLANLabel:       "100",
						OVSInterfaceLabel:  "eth0",
					},
				},
			},
			expectedConfig: &ContainerOVSConfig{
				ContainerID: "test-container-123",
				IPAddress:   "192.168.1.100/24",
				Bridge:      "ovs-test",
				Gateway:     "192.168.1.1",
				MTU:         "1500",
				MACAddress:  "02:42:ac:11:00:02",
				Interface:   "eth0",
				VLAN:        "100",
			},
			expectError: false,
		},
		{
			name: "Minimal OVS configuration with defaults",
			containerInfo: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   "test-container-456",
					Name: "/test-minimal",
				},
				Config: &container.Config{
					Labels: map[string]string{
						OVSIPAddressLabel: "10.0.0.50/24",
					},
				},
			},
			expectedConfig: &ContainerOVSConfig{
				ContainerID: "test-container-456",
				IPAddress:   "10.0.0.50/24",
				Bridge:      "ovsbr0", // default
				Gateway:     "",
				MTU:         "",
				MACAddress:  "",
				Interface:   "eth1", // default
				VLAN:        "",
			},
			expectError: false,
		},
		{
			name: "No OVS labels - should return nil",
			containerInfo: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   "test-container-789",
					Name: "/test-no-ovs",
				},
				Config: &container.Config{
					Labels: map[string]string{
						"other.label": "value",
					},
				},
			},
			expectedConfig: nil,
			expectError:    false,
		},
		{
			name: "No labels at all",
			containerInfo: types.ContainerJSON{
				ContainerJSONBase: &types.ContainerJSONBase{
					ID:   "test-container-000",
					Name: "/test-no-labels",
				},
				Config: &container.Config{
					Labels: nil,
				},
			},
			expectedConfig: nil,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := m.extractOVSConfig(
				tt.containerInfo.ContainerJSONBase.ID,
				tt.containerInfo.Config.Labels,
			)

			if tt.expectError {
				// Currently extractOVSConfig doesn't return errors, but this is here for future expansion
				return
			}

			if tt.expectedConfig == nil {
				if config != nil {
					t.Errorf("Expected nil config, got %+v", config)
				}
				return
			}

			if config == nil {
				t.Errorf("Expected config %+v, got nil", tt.expectedConfig)
				return
			}

			// Compare all fields
			if config.ContainerID != tt.expectedConfig.ContainerID {
				t.Errorf(
					"ContainerID = %s, want %s",
					config.ContainerID,
					tt.expectedConfig.ContainerID,
				)
			}
			if config.IPAddress != tt.expectedConfig.IPAddress {
				t.Errorf("IPAddress = %s, want %s", config.IPAddress, tt.expectedConfig.IPAddress)
			}
			if config.Bridge != tt.expectedConfig.Bridge {
				t.Errorf("Bridge = %s, want %s", config.Bridge, tt.expectedConfig.Bridge)
			}
			if config.Gateway != tt.expectedConfig.Gateway {
				t.Errorf("Gateway = %s, want %s", config.Gateway, tt.expectedConfig.Gateway)
			}
			if config.MTU != tt.expectedConfig.MTU {
				t.Errorf("MTU = %s, want %s", config.MTU, tt.expectedConfig.MTU)
			}
			if config.MACAddress != tt.expectedConfig.MACAddress {
				t.Errorf(
					"MACAddress = %s, want %s",
					config.MACAddress,
					tt.expectedConfig.MACAddress,
				)
			}
			if config.Interface != tt.expectedConfig.Interface {
				t.Errorf("Interface = %s, want %s", config.Interface, tt.expectedConfig.Interface)
			}
			if config.VLAN != tt.expectedConfig.VLAN {
				t.Errorf("VLAN = %s, want %s", config.VLAN, tt.expectedConfig.VLAN)
			}
		})
	}
}

func TestValidateOVSConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *ContainerOVSConfig
		expectValid bool
		description string
	}{
		{
			name: "Valid complete configuration",
			config: &ContainerOVSConfig{
				ContainerID: "test-123",
				IPAddress:   "192.168.1.100/24",
				Bridge:      "ovsbr0",
				Gateway:     "192.168.1.1",
				MTU:         "1500",
				MACAddress:  "02:42:ac:11:00:02",
				Interface:   "eth0",
				VLAN:        "100",
			},
			expectValid: true,
			description: "All fields properly set",
		},
		{
			name: "Valid minimal configuration",
			config: &ContainerOVSConfig{
				ContainerID: "test-456",
				IPAddress:   "10.0.0.50/24",
				Bridge:      "ovsbr0",
				Interface:   "eth1",
			},
			expectValid: true,
			description: "Required fields only",
		},
		{
			name: "Invalid - no container ID",
			config: &ContainerOVSConfig{
				IPAddress: "192.168.1.100/24",
				Bridge:    "ovsbr0",
				Interface: "eth0",
			},
			expectValid: false,
			description: "Missing container ID",
		},
		{
			name: "Invalid - no IP address",
			config: &ContainerOVSConfig{
				ContainerID: "test-789",
				Bridge:      "ovsbr0",
				Interface:   "eth0",
			},
			expectValid: false,
			description: "Missing IP address",
		},
		{
			name: "Invalid - no bridge",
			config: &ContainerOVSConfig{
				ContainerID: "test-000",
				IPAddress:   "192.168.1.100/24",
				Interface:   "eth0",
			},
			expectValid: false,
			description: "Missing bridge",
		},
		{
			name: "Invalid - no interface",
			config: &ContainerOVSConfig{
				ContainerID: "test-111",
				IPAddress:   "192.168.1.100/24",
				Bridge:      "ovsbr0",
			},
			expectValid: false,
			description: "Missing interface",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check basic validation logic
			isValid := tt.config != nil &&
				tt.config.ContainerID != "" &&
				tt.config.IPAddress != "" &&
				tt.config.Bridge != "" &&
				tt.config.Interface != ""

			if isValid != tt.expectValid {
				t.Errorf(
					"Config validation = %v, want %v. %s",
					isValid,
					tt.expectValid,
					tt.description,
				)
				t.Logf("Config: %+v", tt.config)
			}
		})
	}
}
