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
				t.Errorf("Peer name %s length %d exceeds limit %d", peerName, len(peerName), InterfaceNameLimit)
			}
		})
	}
}

func TestPortNameLengthLimits(t *testing.T) {
	m := &Manager{}
	
	// Test with various container ID lengths
	containerIDs := []string{
		"1322aba3640c",                                                               // 12 chars
		"1322aba3640c7f8a",                                                           // 16 chars
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
				t.Errorf("Peer name %s length %d exceeds kernel limit %d", peerName, len(peerName), InterfaceNameLimit)
			}
			
			// Verify port name matches the first 12 chars of container ID
			if portName != containerID[:12] {
				t.Errorf("Port name %s doesn't match container ID prefix %s", portName, containerID[:12])
			}
		})
	}
}
