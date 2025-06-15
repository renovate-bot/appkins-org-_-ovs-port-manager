package manager

import (
	"fmt"
	"net"

	"github.com/google/uuid"
)

var ovsPortManagerNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

// generateDeterministicMAC creates a deterministic MAC address based on an IP address.
// This ensures that the same IP always generates the same MAC address for ARP neighbor consistency.
func generateDeterministicMAC(ipAddr string) (net.HardwareAddr, error) {
	if ipAddr == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}

	// Parse the IP to validate it
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	// Generate a deterministic UUID based on the IP address
	macUUID := uuid.NewSHA1(ovsPortManagerNamespace, []byte("mac:"+ipAddr))

	// Convert UUID to MAC address
	// Use the first 6 bytes of the UUID as MAC address
	uuidBytes := macUUID[:]

	// Create MAC address with local administered bit set (bit 1 of first octet)
	// This ensures it's a locally administered MAC and won't conflict with real hardware
	mac := make(net.HardwareAddr, 6)
	copy(mac, uuidBytes[:6])

	// Set the locally administered bit (bit 1) and clear multicast bit (bit 0)
	mac[0] = (mac[0] & 0xFC) | 0x02 // xxxx xx10 pattern

	return mac, nil
}
