package manager

import (
	"testing"
)

func TestGeneratePortNameExtended(t *testing.T) {
	// Create a basic manager instance
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
		{
			name:        "Very short container ID",
			containerID: "short",
			expected:    "short",
		},
		{
			name:        "Exactly 12 characters",
			containerID: "abcdef123456",
			expected:    "abcdef123456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.generatePortName(tt.containerID)
			if result != tt.expected {
				t.Errorf("generatePortName(%s) = %s, want %s", tt.containerID, result, tt.expected)
			}

			// Verify the name with suffix doesn't exceed the limit
			hostSide := result + "_l"
			containerSide := result + "_c"

			if len(hostSide) > InterfaceNameLimit {
				t.Errorf(
					"Host side name %s length %d exceeds limit %d",
					hostSide,
					len(hostSide),
					InterfaceNameLimit,
				)
			}

			if len(containerSide) > InterfaceNameLimit {
				t.Errorf(
					"Container side name %s length %d exceeds limit %d",
					containerSide,
					len(containerSide),
					InterfaceNameLimit,
				)
			}
		})
	}
}

func TestPortNameConsistency(t *testing.T) {
	m := &Manager{}
	containerID := "1322aba3640c7f8a9b2e5d8f3c1a5b9e8d7c6f2a4b3e1d9c8f7a6b5e4d3c2a1b0"

	// Generate port name multiple times and ensure consistency
	name1 := m.generatePortName(containerID)
	name2 := m.generatePortName(containerID)
	name3 := m.generatePortName(containerID)

	if name1 != name2 || name2 != name3 {
		t.Errorf("Port name generation is not consistent: %s, %s, %s", name1, name2, name3)
	}
}

func TestPortNameLimits(t *testing.T) {
	m := &Manager{}

	// Test various length container IDs
	testCases := []struct {
		containerID string
		description string
	}{
		{"a", "single character"},
		{"abc123", "6 characters"},
		{"abc123def456", "exactly 12 characters"},
		{"abc123def456789", "15 characters"},
		{
			"1322aba3640c7f8a9b2e5d8f3c1a5b9e8d7c6f2a4b3e1d9c8f7a6b5e4d3c2a1b0",
			"full 64 character container ID",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			portName := m.generatePortName(tc.containerID)

			// Check that port name is not empty
			if portName == "" {
				t.Errorf("Port name is empty for container ID: %s", tc.containerID)
			}

			// Check that port name is at most 12 characters
			if len(portName) > 12 {
				t.Errorf(
					"Port name %s (%d chars) exceeds 12 character limit",
					portName,
					len(portName),
				)
			}

			// Check that veth names don't exceed kernel limit
			hostSide := portName + "_l"
			containerSide := portName + "_c"

			if len(hostSide) > InterfaceNameLimit {
				t.Errorf("Host side name %s (%d chars) exceeds kernel limit %d",
					hostSide, len(hostSide), InterfaceNameLimit)
			}

			if len(containerSide) > InterfaceNameLimit {
				t.Errorf("Container side name %s (%d chars) exceeds kernel limit %d",
					containerSide, len(containerSide), InterfaceNameLimit)
			}

			// Verify the port name is a prefix of the container ID (if container ID is long enough)
			if len(tc.containerID) >= len(portName) {
				expectedPrefix := tc.containerID[:len(portName)]
				if portName != expectedPrefix {
					t.Errorf(
						"Port name %s is not a prefix of container ID %s",
						portName,
						tc.containerID,
					)
				}
			}
		})
	}
}

func TestInterfaceNameLimits(t *testing.T) {
	// Test that our constants and naming scheme respects Linux kernel limits
	if InterfaceNameLimit != 15 {
		t.Errorf("InterfaceNameLimit should be 15 (IFNAMSIZ-1), got %d", InterfaceNameLimit)
	}

	// Test some known problematic cases
	m := &Manager{}

	// Test the longest possible port name we might generate (12 chars + 2 char suffix)
	longContainerID := "123456789012abcdefghijklmnop" // 27 chars, should be truncated to 12
	portName := m.generatePortName(longContainerID)

	hostSide := portName + "_l"
	containerSide := portName + "_c"

	// These should be exactly 14 characters ("123456789012_l", "123456789012_c")
	expectedLength := 14
	if len(hostSide) != expectedLength {
		t.Errorf(
			"Host side name %s length %d, expected %d",
			hostSide,
			len(hostSide),
			expectedLength,
		)
	}
	if len(containerSide) != expectedLength {
		t.Errorf(
			"Container side name %s length %d, expected %d",
			containerSide,
			len(containerSide),
			expectedLength,
		)
	}

	// Both should be well under the 15 character kernel limit
	if len(hostSide) > InterfaceNameLimit {
		t.Errorf("Host side name %s exceeds kernel limit", hostSide)
	}
	if len(containerSide) > InterfaceNameLimit {
		t.Errorf("Container side name %s exceeds kernel limit", containerSide)
	}
}
