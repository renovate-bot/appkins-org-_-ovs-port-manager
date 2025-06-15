package manager

import (
	"net"
	"testing"
)

func TestGenerateDeterministicMAC(t *testing.T) {
	tests := []struct {
		name      string
		ipAddr    string
		expectErr bool
		checkFunc func(mac net.HardwareAddr) bool
	}{
		{
			name:      "Valid IPv4 address",
			ipAddr:    "192.168.1.1",
			expectErr: false,
			checkFunc: func(mac net.HardwareAddr) bool {
				// Check that MAC is 6 bytes
				if len(mac) != 6 {
					return false
				}
				// Check that locally administered bit is set (bit 1 of first octet)
				// and multicast bit is clear (bit 0 of first octet)
				// Should be xxxx xx10 pattern
				return (mac[0]&0x02) != 0 && (mac[0]&0x01) == 0
			},
		},
		{
			name:      "Valid IPv6 address",
			ipAddr:    "2001:db8::1",
			expectErr: false,
			checkFunc: func(mac net.HardwareAddr) bool {
				return len(mac) == 6 && (mac[0]&0x02) != 0 && (mac[0]&0x01) == 0
			},
		},
		{
			name:      "Deterministic - same IP produces same MAC",
			ipAddr:    "10.0.0.1",
			expectErr: false,
			checkFunc: func(mac net.HardwareAddr) bool {
				// Generate the same MAC again and compare
				mac2, err := generateDeterministicMAC("10.0.0.1")
				if err != nil {
					return false
				}
				return mac.String() == mac2.String()
			},
		},
		{
			name:      "Empty IP address",
			ipAddr:    "",
			expectErr: true,
			checkFunc: nil,
		},
		{
			name:      "Invalid IP address",
			ipAddr:    "invalid-ip",
			expectErr: true,
			checkFunc: nil,
		},
		{
			name:      "Invalid IP format",
			ipAddr:    "300.400.500.600",
			expectErr: true,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, err := generateDeterministicMAC(tt.ipAddr)

			if tt.expectErr {
				if err == nil {
					t.Errorf("generateDeterministicMAC(%s) expected error, got nil", tt.ipAddr)
				}
				return
			}

			if err != nil {
				t.Errorf("generateDeterministicMAC(%s) unexpected error: %v", tt.ipAddr, err)
				return
			}

			if tt.checkFunc != nil && !tt.checkFunc(mac) {
				t.Errorf("generateDeterministicMAC(%s) = %s, failed validation", tt.ipAddr, mac.String())
			}
		})
	}
}

func TestGenerateDeterministicMACConsistency(t *testing.T) {
	// Test that the same IP always generates the same MAC across multiple calls
	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"2001:db8::1",
	}

	for _, ip := range testIPs {
		t.Run("IP_"+ip, func(t *testing.T) {
			mac1, err1 := generateDeterministicMAC(ip)
			mac2, err2 := generateDeterministicMAC(ip)

			if err1 != nil || err2 != nil {
				t.Errorf("Unexpected errors: %v, %v", err1, err2)
				return
			}

			if mac1.String() != mac2.String() {
				t.Errorf("MAC addresses not consistent for IP %s: %s != %s", ip, mac1.String(), mac2.String())
			}
		})
	}
}

func TestGenerateDeterministicMACUniqueness(t *testing.T) {
	// Test that different IPs generate different MAC addresses
	testIPs := []string{
		"192.168.1.1",
		"192.168.1.2",
		"10.0.0.1",
		"172.16.0.1",
	}

	macs := make(map[string]string)

	for _, ip := range testIPs {
		mac, err := generateDeterministicMAC(ip)
		if err != nil {
			t.Errorf("Unexpected error for IP %s: %v", ip, err)
			continue
		}

		macStr := mac.String()
		if existingIP, exists := macs[macStr]; exists {
			t.Errorf("MAC collision: IP %s and %s both generated MAC %s", ip, existingIP, macStr)
		}
		macs[macStr] = ip
	}
}