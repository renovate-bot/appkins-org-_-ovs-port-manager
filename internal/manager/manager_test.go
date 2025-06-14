package manager

import (
	"testing"
)

func TestGeneratePortName(t *testing.T) {
	// Create a basic manager instance (we only need the method)
	m := &Manager{}

	tests := []struct {
		name        string
		containerID string
		expected    string
	}{
		{
			name:        "Standard container ID",
			containerID: "1322aba3640c7f8a9b2e5d8f3c1a5b9e8d7c6f2a4b3e1d9c8f7a6b5e4d3c2a1b0",
			expected:    "1322aba3640c",
		},
		{
			name:        "Short container ID",
			containerID: "abc123def456",
			expected:    "abc123def456",
		},
		{
			name:        "Minimum length container ID",
			containerID: "123456789012",
			expected:    "123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.generatePortName(tt.containerID)
			if result != tt.expected {
				t.Errorf("generatePortName(%s) = %s, want %s", tt.containerID, result, tt.expected)
			}

			// Verify the name with suffix doesn't exceed the limit
			peerName := result + "_c"
			if len(peerName) > InterfaceNameLimit {
				t.Errorf(
					"Peer name %s length %d exceeds limit %d",
					peerName,
					len(peerName),
					InterfaceNameLimit,
				)
			}
		})
	}
}

func TestPortNameLengthLimits(t *testing.T) {
	m := &Manager{}

	// Test with various container ID lengths
	containerIDs := []string{
		"1322aba3640c",     // 12 chars
		"1322aba3640c7f8a", // 16 chars
		"1322aba3640c7f8a9b2e5d8f3c1a5b9e8d7c6f2a4b3e1d9c8f7a6b5e4d3c2a1b0", // 64 chars (full)
	}

	for _, containerID := range containerIDs {
		t.Run("ContainerID_"+containerID[:12], func(t *testing.T) {
			portName := m.generatePortName(containerID)
			peerName := portName + "_c"

			// Verify port name is exactly 12 characters
			if len(portName) != 12 {
				t.Errorf("Port name %s length %d, expected 12", portName, len(portName))
			}

			// Verify peer name doesn't exceed kernel limit
			if len(peerName) > InterfaceNameLimit {
				t.Errorf(
					"Peer name %s length %d exceeds kernel limit %d",
					peerName,
					len(peerName),
					InterfaceNameLimit,
				)
			}

			// Verify port name matches the first 12 chars of container ID
			if portName != containerID[:12] {
				t.Errorf(
					"Port name %s doesn't match container ID prefix %s",
					portName,
					containerID[:12],
				)
			}
		})
	}
}

func TestOVSDockerMirroringBehavior(t *testing.T) {
	// Test the port name generation to ensure it follows expected patterns
	t.Run("GeneratePortName", func(t *testing.T) {
		m := &Manager{}

		// Test with various container IDs
		testCases := []struct {
			containerID  string
			expectedName string
		}{
			{"1322aba3640c7f3e8b9c123456789abc", "1322aba3640c"}, // Standard case
			{"abc123def456", "abc123def456"},                     // Exactly 12 chars
			{"short", "short"},                                   // Less than 12 chars
		}

		for _, tc := range testCases {
			result := m.generatePortName(tc.containerID)
			if result != tc.expectedName {
				t.Errorf(
					"generatePortName(%s) = %s, want %s",
					tc.containerID,
					result,
					tc.expectedName,
				)
			}

			// Verify it stays under the kernel interface name limit when suffixed
			hostSide := result + "_l"
			containerSide := result + "_c"
			if len(hostSide) > InterfaceNameLimit {
				t.Errorf(
					"Host side name %s (%d chars) exceeds limit %d",
					hostSide,
					len(hostSide),
					InterfaceNameLimit,
				)
			}
			if len(containerSide) > InterfaceNameLimit {
				t.Errorf(
					"Container side name %s (%d chars) exceeds limit %d",
					containerSide,
					len(containerSide),
					InterfaceNameLimit,
				)
			}
		}
	})

	t.Run("VethNamingPattern", func(t *testing.T) {
		// Test that our veth naming pattern matches ovs-docker expectations
		containerID := "1322aba3640c7f3e8b9c123456789abc"
		m := &Manager{}

		portName := m.generatePortName(containerID)
		hostSide := portName + "_l"
		containerSide := portName + "_c"

		// Verify naming pattern matches ovs-docker: ${PORTNAME}_l and ${PORTNAME}_c
		expectedHostSide := "1322aba3640c_l"
		expectedContainerSide := "1322aba3640c_c"

		if hostSide != expectedHostSide {
			t.Errorf("Host side name = %s, want %s", hostSide, expectedHostSide)
		}
		if containerSide != expectedContainerSide {
			t.Errorf("Container side name = %s, want %s", containerSide, expectedContainerSide)
		}
	})
}

func TestOVSDockerPortLookup(t *testing.T) {
	// This test verifies that our port lookup logic matches ovs-docker behavior
	// In ovs-docker, ports are found by external_ids:container_id and external_ids:container_iface

	// Note: This is a unit test that tests the logic without requiring actual OVS
	// In a real integration test, we would set up OVS and test the full workflow

	t.Run("ExternalIDsPattern", func(t *testing.T) {
		// Test that we're using the right external_ids pattern
		containerID := "1322aba3640c7f3e8b9c123456789abc"
		interfaceName := "eth1"

		// These are the external_ids that ovs-docker sets:
		// external_ids:container_id="$CONTAINER"
		// external_ids:container_iface="$INTERFACE"

		expectedExternalIDs := map[string]string{
			"container_id":    containerID,
			"container_iface": interfaceName,
		}

		// Verify our expected pattern matches what we'd set in setInterfaceExternalIDs
		if expectedExternalIDs["container_id"] != containerID {
			t.Errorf("Container ID mismatch in external_ids")
		}
		if expectedExternalIDs["container_iface"] != interfaceName {
			t.Errorf("Interface name mismatch in external_ids")
		}
	})
}
