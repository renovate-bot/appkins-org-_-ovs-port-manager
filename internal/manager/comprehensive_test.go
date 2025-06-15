package manager

import (
	"testing"
)

// TestSuite runs a comprehensive test of core functionality
func TestSuite(t *testing.T) {
	t.Run("MAC Generation", func(t *testing.T) {
		// Test deterministic MAC generation
		mac1, err1 := generateDeterministicMAC("192.168.1.1")
		mac2, err2 := generateDeterministicMAC("192.168.1.1")
		
		if err1 != nil || err2 != nil {
			t.Fatalf("MAC generation failed: %v, %v", err1, err2)
		}
		
		if mac1.String() != mac2.String() {
			t.Errorf("MAC generation not deterministic: %s != %s", mac1.String(), mac2.String())
		}
		
		// Check locally administered bit
		if (mac1[0] & 0x02) == 0 {
			t.Errorf("MAC %s does not have locally administered bit set", mac1.String())
		}
		
		// Check multicast bit is clear
		if (mac1[0] & 0x01) != 0 {
			t.Errorf("MAC %s has multicast bit set", mac1.String())
		}
	})
	
	t.Run("Port Name Generation", func(t *testing.T) {
		m := &Manager{}
		
		// Test standard container ID
		containerID := "1322aba3640c7f8a9b2e5d8f3c1a5b9e"
		portName := m.generatePortName(containerID)
		
		expected := "1322aba3640c"
		if portName != expected {
			t.Errorf("Port name = %s, want %s", portName, expected)
		}
		
		// Test interface name limits
		hostSide := portName + "_l"
		containerSide := portName + "_c"
		
		if len(hostSide) > InterfaceNameLimit {
			t.Errorf("Host side name %s exceeds limit", hostSide)
		}
		
		if len(containerSide) > InterfaceNameLimit {
			t.Errorf("Container side name %s exceeds limit", containerSide)
		}
	})
	
	t.Run("Constants Validation", func(t *testing.T) {
		// Verify our constants are correct
		if InterfaceNameLimit != 15 {
			t.Errorf("InterfaceNameLimit should be 15, got %d", InterfaceNameLimit)
		}
		
		// Check OVS label constants
		expectedLabels := map[string]string{
			"ovs.ip_address":  OVSIPAddressLabel,
			"ovs.bridge":      OVSBridgeLabel,
			"ovs.gateway":     OVSGatewayLabel,
			"ovs.mtu":         OVSMTULabel,
			"ovs.mac_address": OVSMACAddressLabel,
			"ovs.vlan":        OVSVLANLabel,
			"ovs.interface":   OVSInterfaceLabel,
		}
		
		for expected, actual := range expectedLabels {
			if actual != expected {
				t.Errorf("Label constant mismatch: got %s, want %s", actual, expected)
			}
		}
	})
}

// TestErrorHandling tests error conditions
func TestErrorHandling(t *testing.T) {
	t.Run("Invalid MAC Generation", func(t *testing.T) {
		_, err := generateDeterministicMAC("")
		if err == nil {
			t.Error("Expected error for empty IP address")
		}
		
		_, err = generateDeterministicMAC("invalid-ip")
		if err == nil {
			t.Error("Expected error for invalid IP address")
		}
	})
}

// BenchmarkMACGeneration benchmarks MAC address generation
func BenchmarkMACGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = generateDeterministicMAC("192.168.1.1")
	}
}

// BenchmarkPortNameGeneration benchmarks port name generation
func BenchmarkPortNameGeneration(b *testing.B) {
	m := &Manager{}
	containerID := "1322aba3640c7f8a9b2e5d8f3c1a5b9e8d7c6f2a4b3e1d9c8f7a6b5e4d3c2a1b0"
	
	for i := 0; i < b.N; i++ {
		_ = m.generatePortName(containerID)
	}
}
