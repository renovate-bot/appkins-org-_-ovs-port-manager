package main

import (
	"fmt"

	"github.com/google/uuid"
)

func main() {
	ns := uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	
	// Test interface UUID generation
	interfaceUUID := uuid.NewSHA1(ns, []byte("interface:test123_l")).String()
	fmt.Printf("Interface UUID: %s\n", interfaceUUID)
	
	// Test port UUID generation  
	portUUID := uuid.NewSHA1(ns, []byte("port:test123_l")).String()
	fmt.Printf("Port UUID: %s\n", portUUID)
	
	// Test that same input generates same UUID
	interfaceUUID2 := uuid.NewSHA1(ns, []byte("interface:test123_l")).String()
	fmt.Printf("Interface UUID (repeat): %s\n", interfaceUUID2)
	fmt.Printf("UUIDs match: %t\n", interfaceUUID == interfaceUUID2)
}
