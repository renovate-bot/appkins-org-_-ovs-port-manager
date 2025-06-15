package manager

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// getContainerSandboxKey gets the sandbox key for a container's network namespace.
func (m *Manager) getContainerSandboxKey(
	ctx context.Context,
	containerID string,
	logger logr.Logger,
) (string, error) {
	container, err := m.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		logger.V(1).Error(err, "Failed to inspect container", "container_id", containerID[:12])
		return "", fmt.Errorf("failed to inspect container %s: %w", containerID[:12], err)
	}

	if container.State.Pid == 0 {
		logger.V(1).Info("Container is not running", "container_id", containerID[:12])
		return "", fmt.Errorf("container %s is not running", containerID[:12])
	}

	if container.NetworkSettings.SandboxKey == "" {
		logger.V(1).Info("Container has no sandbox ID", "container_id", containerID[:12])
		return "", fmt.Errorf("container %s has no sandbox ID", containerID[:12])
	}

	return container.NetworkSettings.SandboxKey, nil
}

// getContainerFd gets a file descriptor for the container's network namespace with proper cleanup.
func (m *Manager) getContainerFd(
	ctx context.Context,
	containerID string,
	logger logr.Logger,
) (int, func(), error) {
	netnsPath, err := m.getContainerSandboxKey(ctx, containerID, logger)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get container sandbox ID: %w", err)
	}

	// Use Docker's netns path via SandboxKey for more reliable access
	fd, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to open netns %s: %w", netnsPath, err)
	}

	cleanup := func() {
		if err := unix.Close(fd); err != nil {
			// Log error but don't fail the operation - this is cleanup
			logger.V(1).Info("Failed to close container netns fd", "error", err)
		}
	}

	return fd, cleanup, nil
}

// setLinkUp sets a network interface up.
func (m *Manager) setLinkUp(
	interfaceName string,
	logger logr.Logger,
) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		logger.V(1).Error(err, "Failed to find link", "interface", interfaceName)
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		logger.V(1).Error(err, "Failed to set link up", "interface", interfaceName)
		return fmt.Errorf("failed to set link %s up: %v", interfaceName, err)
	}

	return nil
}

// configureInterfaceInContainer configures an interface inside a container using Docker ID.
// The newFriendlyName parameter is the target friendly interface name.
func (m *Manager) configureInterfaceInContainer(
	ctx context.Context,
	containerID, oldName, newFriendlyName, ipAddr, macAddr, mtu, gateway string,
	logger logr.Logger,
) error {
	// Get container namespace file descriptor
	fd, cleanup, err := m.getContainerFd(ctx, containerID, logger)
	if err != nil {
		return fmt.Errorf("failed to get container fd: %w", err)
	}
	defer cleanup()

	// Create a netlink handle for the container namespace
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(fd))
	if err != nil {
		return fmt.Errorf("failed to create netlink handle for container namespace: %w", err)
	}
	defer nsHandle.Delete()

	currentNameInNamespace := oldName // The name of the link as it was passed into the namespace

	// Rename interface to the friendly name if specified and different from the current name
	if newFriendlyName != "" && currentNameInNamespace != newFriendlyName {
		_, err := m.renameToFriendlyInterfaceNameWithHandle(
			nsHandle,
			currentNameInNamespace,
			newFriendlyName,
			logger,
		)
		if err != nil {
			return fmt.Errorf(
				"failed to rename interface from %s to %s in container %s: %w",
				currentNameInNamespace,
				newFriendlyName,
				containerID[:12],
				err,
			)
		}
		// After successful rename, the interface to be configured is now newFriendlyName
		currentNameInNamespace = newFriendlyName
		logger.V(3).Info("Successfully renamed interface in container",
			"container_id", containerID[:12], "old_name", oldName, "new_name", newFriendlyName)
	}

	// Configure the interface within the container namespace using its current (possibly new) name
	if err := m.configureInterfaceWithHandle(nsHandle, currentNameInNamespace, ipAddr, macAddr, mtu, gateway, logger); err != nil {
		// Pass up error, context should be sufficient from configureInterfaceWithHandle
		return err
	}

	logger.V(2).Info("Configured interface in container",
		"container_id", containerID[:12], "original_name_in_ns", oldName,
		"final_name_in_ns", currentNameInNamespace, "ip_address", ipAddr)

	return nil
}

// deleteLinkByName deletes a network interface by name.
func (m *Manager) deleteLinkByName(
	interfaceName string,
	logger logr.Logger,
) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// Interface doesn't exist, consider it already cleaned up
		if strings.Contains(err.Error(), "Link not found") {
			return nil
		}
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", interfaceName, err)
	}

	logger.V(3).Info("Deleted network interface", "interface", interfaceName)
	return nil
}

// createVethPairWithNames creates a veth pair with specific names.
func (m *Manager) createVethPairWithNames(
	hostSide, containerSide string,
	fd int,
	logger logr.Logger,
) error {
	logger.V(3).Info("Creating veth pair",
		"host_side", hostSide, "container_side", containerSide)

	// Check if host side already exists and clean it up first
	if existingLink, err := netlink.LinkByName(hostSide); err == nil {
		logger.V(2).Info("Host side interface already exists, deleting",
			"interface", hostSide)
		if delErr := netlink.LinkDel(existingLink); delErr != nil {
			logger.V(1).Info("Failed to delete existing host side interface",
				"error", delErr, "interface", hostSide)
			// Continue with creation attempt - might be a different type of interface
		} else {
			logger.V(3).Info("Successfully deleted existing host side interface",
				"interface", hostSide)
		}
	}

	// Create the veth pair with container side going directly to target namespace
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostSide,
		},
		PeerName:      containerSide,
		PeerNamespace: netlink.NsFd(fd),
	}

	if err := netlink.LinkAdd(veth); err != nil {
		// Handle specific error cases
		if strings.Contains(err.Error(), "file exists") {
			logger.V(2).Info("Veth pair already exists, checking if we should recreate",
				"host_side", hostSide, "container_side", containerSide)

			// Check if the existing veth pair is for the same container and if the container is running
			if shouldRecreateVethPair, reason := m.shouldRecreateExistingVethPair(hostSide, containerSide, fd, logger); shouldRecreateVethPair {
				logger.V(1).Info("Recreating veth pair", "reason", reason,
					"host_side", hostSide, "container_side", containerSide)

				// Clean up existing pair
				if cleanupErr := m.forceCleanupVethPair(hostSide, containerSide, logger); cleanupErr != nil {
					logger.V(1).Info("Failed to cleanup existing veth pair",
						"error", cleanupErr, "host_side", hostSide)
				}

				// Retry creation after cleanup
				if retryErr := netlink.LinkAdd(veth); retryErr != nil {
					return fmt.Errorf("failed to create veth pair after cleanup: %w", retryErr)
				}
			} else {
				logger.V(2).Info("Keeping existing veth pair", "reason", reason,
					"host_side", hostSide, "container_side", containerSide)
				// Existing veth pair is valid, continue without recreating
			}
		} else if strings.Contains(err.Error(), "invalid argument") {
			// This often indicates namespace issues or name conflicts
			logger.V(1).Info("Invalid argument error during veth creation, checking namespace accessibility",
				"error", err, "host_side", hostSide, "container_side", containerSide)

			return fmt.Errorf("failed to create veth pair - invalid argument (possibly namespace or naming issue): %w", err)
		} else {
			return fmt.Errorf("failed to create veth pair: %w", err)
		}
	}

	// Verify host side interface exists after creation
	if _, err := netlink.LinkByName(hostSide); err != nil {
		return fmt.Errorf("host side interface %s not found after creation: %w", hostSide, err)
	}

	logger.V(3).Info("Veth pair created successfully",
		"host_side", hostSide, "container_side", containerSide)

	return nil
}

// forceCleanupVethPair aggressively cleans up both sides of a veth pair.
// This method attempts to remove interfaces by name from both the host and any
// accessible namespaces to ensure no remnants exist before retrying veth creation.
func (m *Manager) forceCleanupVethPair(hostSide, containerSide string, logger logr.Logger) error {
	var errors []error

	logger.V(2).Info("Force cleaning up veth pair",
		"host_side", hostSide, "container_side", containerSide)

	// Try to clean up host side interface
	if hostLink, err := netlink.LinkByName(hostSide); err == nil {
		logger.V(3).Info("Found host side interface, attempting deletion", "interface", hostSide)
		if delErr := netlink.LinkDel(hostLink); delErr != nil {
			errors = append(errors, fmt.Errorf(
				"failed to delete host side interface %s: %w", hostSide, delErr))
			logger.V(2).Info("Failed to delete host side interface",
				"error", delErr, "interface", hostSide)
		} else {
			logger.V(3).Info("Successfully deleted host side interface", "interface", hostSide)
		}
	} else {
		logger.V(3).Info("Host side interface not found", "interface", hostSide)
	}

	// Try to clean up any interfaces with the container side name in current namespace
	// (in case it exists in the host namespace for some reason)
	if containerLink, err := netlink.LinkByName(containerSide); err == nil {
		logger.V(3).Info("Found container side interface in host namespace, attempting deletion",
			"interface", containerSide)
		if delErr := netlink.LinkDel(containerLink); delErr != nil {
			errors = append(errors, fmt.Errorf(
				"failed to delete container side interface %s from host namespace: %w",
				containerSide, delErr))
			logger.V(2).Info("Failed to delete container side interface from host namespace",
				"error", delErr, "interface", containerSide)
		} else {
			logger.V(3).Info("Successfully deleted container side interface from host namespace",
				"interface", containerSide)
		}
	}

	// Get list of all network namespaces to check for stray interfaces
	// We'll check common namespace paths where the container side might exist
	namespacePaths := []string{
		"/var/run/netns/" + containerSide, // Named namespaces
		"/var/run/docker/netns",           // Docker namespaces directory
	}

	// Try to enumerate Docker namespace files
	if entries, err := os.ReadDir("/var/run/docker/netns"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			namespacePaths = append(namespacePaths, "/var/run/docker/netns/"+entry.Name())
		}
	}

	// For each potential namespace, try to clean up the container side interface
	for _, nsPath := range namespacePaths {
		if err := m.cleanupContainerSideFromNamespace(nsPath, containerSide, logger); err != nil {
			errors = append(errors, err)
		}
	}

	// Wait a short time for interface cleanup to propagate
	time.Sleep(100 * time.Millisecond)

	if len(errors) > 0 {
		// Return combined error but don't fail completely - partial cleanup might be enough
		logger.V(2).Info("Some cleanup operations failed", "error_count", len(errors))
		return fmt.Errorf("partial cleanup failures: %v", errors)
	}

	logger.V(3).Info("Force cleanup completed successfully",
		"host_side", hostSide, "container_side", containerSide)
	return nil
}

// cleanupContainerSideFromNamespace attempts to clean up a container-side interface from a specific namespace.
// This function uses defer to ensure proper resource cleanup.
func (m *Manager) cleanupContainerSideFromNamespace(nsPath, containerSide string, logger logr.Logger) error {
	// Check if namespace path exists
	if _, err := os.Stat(nsPath); os.IsNotExist(err) {
		logger.V(4).Info("Namespace path does not exist, skipping", "path", nsPath)
		return nil // Not an error - namespace may have been cleaned up already
	}

	// Open the namespace
	ns, err := netns.GetFromPath(nsPath)
	if err != nil {
		logger.V(4).Info("Failed to open namespace for cleanup", "path", nsPath, "error", err)
		return fmt.Errorf("failed to open namespace %s: %w", nsPath, err)
	}
	
	// Ensure namespace is always closed
	defer func() {
		if closeErr := ns.Close(); closeErr != nil {
			logger.V(4).Info("Error closing namespace handle", "path", nsPath, "error", closeErr)
		}
	}()

	// Create a handle for this namespace
	handle, err := netlink.NewHandleAt(ns)
	if err != nil {
		logger.V(4).Info("Failed to create netlink handle for namespace", 
			"path", nsPath, "error", err)
		return fmt.Errorf("failed to create netlink handle for namespace %s: %w", nsPath, err)
	}
	
	// Ensure handle is always closed
	defer func() {
		handle.Close()
		logger.V(4).Info("Closed netlink handle", "path", nsPath)
	}()

	// Try to find and delete the container side interface
	link, err := handle.LinkByName(containerSide)
	if err != nil {
		// Interface not found in this namespace - not an error
		logger.V(4).Info("Container side interface not found in namespace", 
			"interface", containerSide, "namespace", nsPath)
		return nil
	}

	logger.V(3).Info("Found container side interface in namespace, attempting deletion",
		"interface", containerSide, "namespace", nsPath)
	
	if delErr := handle.LinkDel(link); delErr != nil {
		logger.V(2).Info("Failed to delete container side interface from namespace",
			"error", delErr, "interface", containerSide, "namespace", nsPath)
		return fmt.Errorf("failed to delete container side interface %s from namespace %s: %w",
			containerSide, nsPath, delErr)
	}

	logger.V(3).Info("Successfully deleted container side interface from namespace",
		"interface", containerSide, "namespace", nsPath)
	return nil
}

// addARPNeighborWithHandle adds a static ARP neighbor entry using a specific netlink handle.
func (m *Manager) addARPNeighborWithHandle(
	handle *netlink.Handle,
	link netlink.Link,
	ipAddr, macAddr string,
	logger logr.Logger,
) error {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %s", macAddr)
	}

	neigh := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        0x02, // NUD_PERMANENT - permanent ARP entry
		IP:           ip,
		HardwareAddr: mac,
	}

	if err := handle.NeighAdd(neigh); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			logger.V(3).Info("ARP neighbor entry already exists", "ip", ipAddr, "mac", macAddr)
			return nil
		}
		return fmt.Errorf("failed to add neighbor entry: %w", err)
	}

	logger.V(3).Info("Added static ARP neighbor entry", "ip", ipAddr, "mac", macAddr)
	return nil
}

// renameToFriendlyInterfaceNameWithHandle renames a network interface to a user-specified
// or default "friendly" name using a specific netlink handle.
// The oldName is typically a system-generated name (e.g., from veth creation),
// and newName is the desired final name (e.g., "eth0", "eth1") either from
// the OVSInterfaceLabel Docker label or a configuration default.
// It includes a retry mechanism to handle timing issues after renaming.
func (m *Manager) renameToFriendlyInterfaceNameWithHandle(
	handle *netlink.Handle,
	oldName, newName string, // newName is the friendly name
	logger logr.Logger,
) (netlink.Link, error) {
	link, err := handle.LinkByName(oldName)
	if err != nil {
		return nil, fmt.Errorf("failed to find link %s in target namespace: %v", oldName, err)
	}

	// Check if target interface name already exists
	if _, err := handle.LinkByName(newName); err == nil {
		return nil, fmt.Errorf(
			"interface %s already exists, cannot rename %s",
			newName,
			oldName,
		)
	}

	if err := handle.LinkSetName(link, newName); err != nil {
		return nil, fmt.Errorf("failed to rename interface %s to %s: %v", oldName, newName, err)
	}

	// Re-get the link with new name, with retry for timing issues
	var retryErr error
	var renamedLink netlink.Link
	for i := 0; i < 3; i++ { // Use a literal int for loop condition
		if renamedLink, retryErr = handle.LinkByName(newName); retryErr == nil {
			logger.V(3).Info(
				"Successfully found renamed interface",
				"oldName", oldName, "newName", newName,
			)
			return renamedLink, nil
		}
		logger.V(2).Info(
			"Retrying to find renamed interface",
			"attempt", i+1, "oldName", oldName, "newName", newName, "error", retryErr,
		)
		time.Sleep(time.Millisecond * 50) // Small delay
	}

	return nil, fmt.Errorf(
		"failed to find renamed link %s (from %s) after retries: %w",
		newName,
		oldName,
		retryErr,
	)
}

// configureInterfaceWithHandle configures an interface using a specific netlink handle.
// It assumes the interface already has its final intended name in the namespace.
func (m *Manager) configureInterfaceWithHandle(
	handle *netlink.Handle,
	interfaceName, ipAddr, macAddr, mtu, gateway string,
	logger logr.Logger,
) error {
	// Find the interface in the target namespace by its current name
	link, err := handle.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find link %s in target namespace: %v", interfaceName, err)
	}

	// Set MAC address if provided
	if macAddr != "" {
		mac, err := net.ParseMAC(macAddr)
		if err != nil {
			return fmt.Errorf("invalid MAC address %s: %v", macAddr, err)
		}
		if err := handle.LinkSetHardwareAddr(link, mac); err != nil {
			return fmt.Errorf("failed to set MAC address: %v", err)
		}
	}

	// Set MTU if provided
	if mtu != "" {
		mtuInt, err := strconv.Atoi(mtu)
		if err != nil {
			return fmt.Errorf("invalid MTU %s: %v", mtu, err)
		}
		if err := handle.LinkSetMTU(link, mtuInt); err != nil {
			return fmt.Errorf("failed to set MTU: %v", err)
		}
	}

	// Configure IP address
	if ipAddr != "" {
		addr, err := netlink.ParseAddr(ipAddr)
		if err != nil {
			return fmt.Errorf("failed to parse IP address %s: %v", ipAddr, err)
		}
		if err := handle.AddrAdd(link, addr); err != nil {
			// Check if address already exists
			if !strings.Contains(err.Error(), "file exists") {
				return fmt.Errorf("failed to add IP address: %v", err)
			}
		}
	}

	// Set interface up
	if err := handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface %s up: %v", interfaceName, err)
	}

	// Configure gateway if provided
	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway IP %s", gateway)
		}

		// Create default route (0.0.0.0/0 for IPv4, ::/0 for IPv6)
		var dst *net.IPNet
		if gw.To4() != nil {
			// IPv4 default route
			_, dst, _ = net.ParseCIDR("0.0.0.0/0")
		} else {
			// IPv6 default route
			_, dst, _ = net.ParseCIDR("::/0")
		}

		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
			Gw:        gw,
		}

		if err := handle.RouteAdd(route); err != nil {
			// Check if route already exists or if it's a more specific error
			errStr := err.Error()
			if strings.Contains(errStr, "file exists") {
				logger.V(2).Info("Default route already exists, skipping", "gateway", gateway)
			} else if strings.Contains(errStr, "network is unreachable") {
				// This often happens when the gateway is not in the same subnet as the interface IP
				logger.V(1).Info("Gateway unreachable - this may be expected for certain network configurations",
					"gateway", gateway, "interface", interfaceName, "ip", ipAddr, "error", err)
				// Don't fail the operation for now, as this might be intentional
			} else {
				return fmt.Errorf("failed to add gateway route for interface %s: %w", interfaceName, err)
			}
		} else {
			logger.V(2).Info("Added default gateway route", "gateway", gateway, "interface", interfaceName)
		}
	}

	// Add ARP neighbor entry for the gateway if provided
	if ipAddr != "" {
		// Generate a deterministic MAC address for the gateway
		ipAddrMAC, err := generateDeterministicMAC(ipAddr) // Call the local package function
		if err != nil {
			logger.V(1).Info("Failed to generate MAC for interface IP's ARP entry",
				"interface_ip", ipAddr, "error", err)
		} else {
			if err := m.addARPNeighborWithHandle(handle, link, ipAddr, ipAddrMAC.String(), logger); err != nil { // Pass logger
				logger.V(1).Info("Failed to add interface ARP entry",
					"interface_ip", ipAddr, "mac", ipAddrMAC.String(), "error", err)
				// Don't fail the operation for ARP neighbor failures
			}
		}
	}

	logger.V(3).Info("Configured interface with handle",
		"interface", interfaceName, "ip", ipAddr, "mac", macAddr, "mtu", mtu, "gateway", gateway)

	return nil
}

// enableIPForwarding enables IP forwarding on the host.
func (m *Manager) enableIPForwarding() error {
	// Enable IPv4 forwarding
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		// In test environments or containers without /proc mounted, this may fail
		// Check if it's a test environment by looking for specific error patterns
		if os.IsNotExist(err) {
			m.logger.V(2).Info(
				"IPv4 forwarding control file not found, likely in test environment",
				"error", err)
			return nil // Don't fail tests for missing /proc files
		}
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	m.logger.V(2).Info("IPv4 forwarding enabled via /proc/sys/net/ipv4/ip_forward")

	// Enable IPv6 forwarding if configured (though current external routing is IPv4 focused)
	if m.config.Network.EnableIPv6 {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0o644); err != nil {
			// Log as warning, as IPv4 might be primary, and this could be test environment
			if os.IsNotExist(err) {
				m.logger.V(2).Info(
					"IPv6 forwarding control file not found, likely in test environment",
					"error", err)
			} else {
				m.logger.V(1).Error(err, "Failed to enable IPv6 forwarding, continuing with IPv4")
			}
		} else {
			m.logger.V(2).Info("IPv6 forwarding enabled via /proc/sys/net/ipv6/conf/all/forwarding")
		}
	}
	return nil
}

// assignIPToInterface assigns an IP address to a host interface.
// The ipAddress should be in CIDR format (e.g., "192.168.1.100/24").
func (m *Manager) assignIPToInterface(ipAddress, interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find host interface %s: %w", interfaceName, err)
	}

	addr, err := netlink.ParseAddr(ipAddress) // Expects CIDR, e.g., "10.0.0.100/24"
	if err != nil {
		return fmt.Errorf("failed to parse IP address %s: %w", ipAddress, err)
	}

	// Check if address already exists
	addrs, err := netlink.AddrList(link, unix.AF_INET) // Use unix.AF_INET for IPv4
	if err != nil {
		return fmt.Errorf("failed to list addresses for interface %s: %w", interfaceName, err)
	}
	for _, existingAddr := range addrs {
		if existingAddr.IP.Equal(addr.IP) && existingAddr.Mask.String() == addr.Mask.String() {
			m.logger.V(2).Info("IP address already assigned to interface",
				"ip_address", ipAddress, "interface", interfaceName)
			return nil // Already assigned
		}
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf(
			"failed to add IP address %s to interface %s: %w",
			ipAddress,
			interfaceName,
			err,
		)
	}
	m.logger.V(2).Info("Successfully assigned IP address to host interface",
		"ip_address", ipAddress, "interface", interfaceName)
	return nil
}

// removeIPFromInterface removes an IP address from a host interface.
// The ipAddress should be in CIDR format.
func (m *Manager) removeIPFromInterface(ipAddress, interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// If interface doesn't exist, consider IP removed or not applicable
		if strings.Contains(err.Error(), "Link not found") {
			m.logger.V(2).
				Info("Host interface not found, cannot remove IP", "interface", interfaceName)
			return nil
		}
		return fmt.Errorf("failed to find host interface %s: %w", interfaceName, err)
	}

	addr, err := netlink.ParseAddr(ipAddress)
	if err != nil {
		return fmt.Errorf("failed to parse IP address %s: %w", ipAddress, err)
	}

	// Check if address actually exists before trying to delete
	existingAddrs, err := netlink.AddrList(link, unix.AF_INET) // Use unix.AF_INET for IPv4
	if err != nil {
		return fmt.Errorf("failed to list addresses on %s: %w", interfaceName, err)
	}
	found := false
	for _, exAddr := range existingAddrs {
		if exAddr.IP.Equal(addr.IP) && exAddr.Mask.String() == addr.Mask.String() {
			found = true
			break
		}
	}

	if !found {
		m.logger.V(2).Info("IP address not found on interface, no removal needed",
			"ip_address", ipAddress, "interface", interfaceName)
		return nil
	}

	if err := netlink.AddrDel(link, addr); err != nil {
		// If AddrDel returns "no such address", it's fine.
		if strings.Contains(err.Error(), "no such address") {
			m.logger.V(2).Info("IP address already removed or not present on interface",
				"ip_address", ipAddress, "interface", interfaceName)
			return nil
		}
		return fmt.Errorf(
			"failed to delete IP address %s from interface %s: %w",
			ipAddress,
			interfaceName,
			err,
		)
	}
	m.logger.V(2).Info("Successfully removed IP address from host interface",
		"ip_address", ipAddress, "interface", interfaceName)
	return nil
}

// addExternalRoute adds a specific route for an external IP through a host interface.
// This creates a route like: ip route add 169.254.169.254/32 dev veth_interface.
func (m *Manager) addExternalRoute(externalIP, hostInterface string) error {
	// Parse the external IP to determine if it's IPv4 or IPv6
	ip := net.ParseIP(externalIP)
	if ip == nil {
		return fmt.Errorf("invalid external IP address: %s", externalIP)
	}

	// Get the interface
	link, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return fmt.Errorf("failed to find host interface %s: %w", hostInterface, err)
	}

	// Create the destination network (/32 for IPv4, /128 for IPv6)
	var dest *net.IPNet
	if ip.To4() != nil {
		// IPv4 - create a /32 network
		_, dest, err = net.ParseCIDR(externalIP + "/32")
	} else {
		// IPv6 - create a /128 network
		_, dest, err = net.ParseCIDR(externalIP + "/128")
	}

	if err != nil {
		return fmt.Errorf("failed to parse destination network for %s: %w", externalIP, err)
	}

	// Create the route
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dest,
		// Scope defaults to appropriate value for direct interface routes
	}

	// Add the route
	if err := netlink.RouteAdd(route); err != nil {
		// Check if route already exists
		if strings.Contains(err.Error(), "file exists") {
			m.logger.V(2).Info("External route already exists",
				"ip", externalIP, "interface", hostInterface)
			return nil
		}
		return fmt.Errorf("failed to add external route: %w", err)
	}

	m.logger.V(3).Info("Added external route",
		"destination", dest.String(), "interface", hostInterface)
	return nil
}

// removeExternalRoute removes a specific route for an external IP.
func (m *Manager) removeExternalRoute(externalIP, hostInterface string) error {
	// Parse the external IP
	ip := net.ParseIP(externalIP)
	if ip == nil {
		return fmt.Errorf("invalid external IP address: %s", externalIP)
	}

	// Get the interface (may not exist if container/interface was already removed)
	link, err := netlink.LinkByName(hostInterface)
	if err != nil {
		if strings.Contains(err.Error(), "Link not found") {
			m.logger.V(2).Info("Host interface not found, route likely already removed",
				"interface", hostInterface)
			return nil
		}
		return fmt.Errorf("failed to find host interface %s: %w", hostInterface, err)
	}

	// Create the destination network
	var dest *net.IPNet
	if ip.To4() != nil {
		_, dest, err = net.ParseCIDR(externalIP + "/32")
	} else {
		_, dest, err = net.ParseCIDR(externalIP + "/128")
	}

	if err != nil {
		return fmt.Errorf("failed to parse destination network for %s: %w", externalIP, err)
	}

	// Create the route to remove
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dest,
		// Scope defaults to appropriate value
	}

	// Remove the route
	if err := netlink.RouteDel(route); err != nil {
		// Check if route doesn't exist
		if strings.Contains(err.Error(), "no such process") ||
			strings.Contains(err.Error(), "not found") {
			m.logger.V(2).Info("External route not found, likely already removed",
				"ip", externalIP, "interface", hostInterface)
			return nil
		}
		return fmt.Errorf("failed to remove external route: %w", err)
	}

	m.logger.V(3).Info("Removed external route",
		"destination", dest.String(), "interface", hostInterface)
	return nil
}

// addExternalGatewayRoute adds a gateway route for external routing.
// This is optional and mainly for more complex routing scenarios.
func (m *Manager) addExternalGatewayRoute(externalIP, gateway, hostInterface string) error {
	// Parse IPs
	ip := net.ParseIP(externalIP)
	if ip == nil {
		return fmt.Errorf("invalid external IP address: %s", externalIP)
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP address: %s", gateway)
	}

	// Get the interface
	link, err := netlink.LinkByName(hostInterface)
	if err != nil {
		return fmt.Errorf("failed to find host interface %s: %w", hostInterface, err)
	}

	// Create destination network
	var dest *net.IPNet
	if ip.To4() != nil {
		_, dest, err = net.ParseCIDR(externalIP + "/32")
	} else {
		_, dest, err = net.ParseCIDR(externalIP + "/128")
	}

	if err != nil {
		return fmt.Errorf("failed to parse destination network for %s: %w", externalIP, err)
	}

	// Create the gateway route
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dest,
		Gw:        gw,
	}

	// Add the route
	if err := netlink.RouteAdd(route); err != nil {
		if strings.Contains(err.Error(), "file exists") {
			m.logger.V(2).Info("External gateway route already exists",
				"ip", externalIP, "gateway", gateway, "interface", hostInterface)
			return nil
		}
		return fmt.Errorf("failed to add external gateway route: %w", err)
	}

	m.logger.V(3).Info("Added external gateway route",
		"destination", dest.String(), "gateway", gateway, "interface", hostInterface)
	return nil
}

// removeExternalGatewayRoute removes a gateway route for external routing.
func (m *Manager) removeExternalGatewayRoute(externalIP, gateway, hostInterface string) error {
	// Parse IPs
	ip := net.ParseIP(externalIP)
	if ip == nil {
		return fmt.Errorf("invalid external IP address: %s", externalIP)
	}

	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP address: %s", gateway)
	}

	// Get the interface
	link, err := netlink.LinkByName(hostInterface)
	if err != nil {
		if strings.Contains(err.Error(), "Link not found") {
			m.logger.V(2).Info("Host interface not found, gateway route likely already removed",
				"interface", hostInterface)
			return nil
		}
		return fmt.Errorf("failed to find host interface %s: %w", hostInterface, err)
	}

	// Create destination network
	var dest *net.IPNet
	if ip.To4() != nil {
		_, dest, err = net.ParseCIDR(externalIP + "/32")
	} else {
		_, dest, err = net.ParseCIDR(externalIP + "/128")
	}

	if err != nil {
		return fmt.Errorf("failed to parse destination network for %s: %w", externalIP, err)
	}

	// Create the route to remove
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dest,
		Gw:        gw,
	}

	// Remove the route
	if err := netlink.RouteDel(route); err != nil {
		if strings.Contains(err.Error(), "no such process") ||
			strings.Contains(err.Error(), "not found") {
			m.logger.V(2).Info("External gateway route not found, likely already removed",
				"ip", externalIP, "gateway", gateway, "interface", hostInterface)
			return nil
		}
		return fmt.Errorf("failed to remove external gateway route: %w", err)
	}

	m.logger.V(3).Info("Removed external gateway route",
		"destination", dest.String(), "gateway", gateway, "interface", hostInterface)
	return nil
}

// shouldRecreateExistingVethPair determines if an existing veth pair should be recreated.
// This function implements intelligent logic to avoid unnecessary recreation of veth pairs
// that are still valid for the target container.
func (m *Manager) shouldRecreateExistingVethPair(
	hostSide, containerSide string,
	targetFd int,
	logger logr.Logger,
) (bool, string) {
	// Check if host side interface exists
	hostLink, err := netlink.LinkByName(hostSide)
	if err != nil {
		// Host side doesn't exist, we should create
		return true, "host side interface missing"
	}

	// Get the peer index from the host side
	if veth, ok := hostLink.(*netlink.Veth); ok && veth.PeerName != "" {
		// Try to find the peer by name in the target namespace
		targetHandle, err := netlink.NewHandleAt(netns.NsHandle(targetFd))
		if err != nil {
			logger.V(2).Info("Failed to access target namespace, will recreate veth pair",
				"error", err, "host_side", hostSide)
			return true, "cannot access target namespace"
		}
		defer targetHandle.Delete()

		// Check if container side exists in the target namespace
		if _, err := targetHandle.LinkByName(containerSide); err != nil {
			logger.V(2).Info("Container side interface not found in target namespace",
				"container_side", containerSide, "error", err)
			return true, "container side interface missing in target namespace"
		}

		logger.V(3).Info("Existing veth pair is valid for target container",
			"host_side", hostSide, "container_side", containerSide)
		return false, "veth pair already correctly configured for container"
	}

	// Check if an interface with the container name exists in the current (host) namespace
	// This might happen if a previous container cleanup failed
	if _, err := netlink.LinkByName(containerSide); err == nil {
		logger.V(2).Info("Container side interface found in wrong namespace (host)",
			"container_side", containerSide)
		return true, "container side interface in wrong namespace"
	}

	// Default: if we can't determine the state clearly, it's safer to recreate
	logger.V(2).Info("Cannot determine veth pair state clearly, will recreate",
		"host_side", hostSide, "container_side", containerSide)
	return true, "unable to verify existing veth pair state"
}
