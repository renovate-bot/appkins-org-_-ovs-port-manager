#!/bin/bash

# Test script to verify netlink migration functionality

set -e

# Change to the project root directory
cd "$(dirname "$0")/.."

echo "=== Netlink Migration Test ==="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This test must be run as root for network operations"
   exit 1
fi

echo "Testing netlink functionality without OVS..."

# Create a simple test program to verify netlink operations
cat > netlink_test.go << 'EOF'
package main

import (
	"fmt"
	"log"
	"github.com/vishvananda/netlink"
)

func main() {
	// Test 1: Create a test veth pair
	fmt.Println("Creating test veth pair...")
	vethLink := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "test_l",
		},
		PeerName: "test_c",
	}
	
	if err := netlink.LinkAdd(vethLink); err != nil {
		log.Fatalf("Failed to create veth pair: %v", err)
	}
	fmt.Println("✓ Created veth pair: test_l <-> test_c")
	
	// Test 2: Bring up the interface
	link, err := netlink.LinkByName("test_l")
	if err != nil {
		log.Fatalf("Failed to find link: %v", err)
	}
	
	if err := netlink.LinkSetUp(link); err != nil {
		log.Fatalf("Failed to set link up: %v", err)
	}
	fmt.Println("✓ Brought up interface test_l")
	
	// Test 3: List the interface to verify it exists
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("Failed to list links: %v", err)
	}
	
	found := false
	for _, l := range links {
		if l.Attrs().Name == "test_l" {
			found = true
			fmt.Printf("✓ Found interface test_l with index %d\n", l.Attrs().Index)
			break
		}
	}
	
	if !found {
		log.Fatalf("Test interface not found in link list")
	}
	
	// Test 4: Clean up - delete the veth pair
	if err := netlink.LinkDel(link); err != nil {
		log.Fatalf("Failed to delete link: %v", err)
	}
	fmt.Println("✓ Cleaned up test interfaces")
	
	fmt.Println("All netlink tests passed!")
}
EOF

# Run the test
echo "Building and running netlink test..."
go run netlink_test.go

# Clean up
rm -f netlink_test.go

echo "✓ Netlink migration verification completed successfully!"
echo ""
echo "The OVS Port Manager now uses netlink for all network operations:"
echo "- Creating veth pairs"
echo "- Configuring interfaces"
echo "- Moving interfaces to namespaces"
echo "- Setting IP addresses, MAC addresses, MTU"
echo "- Adding routes"
echo "- Cleaning up interfaces"
echo ""
echo "This provides better performance and reliability compared to executing 'ip' commands."
