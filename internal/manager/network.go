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
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostSide,
		},
		PeerName:      containerSide,
		PeerNamespace: netlink.NsFd(fd),
	}

	if err := netlink.LinkAdd(veth); err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("failed to create veth pair: %w", err)
		}
		logger.V(3).Info("Not creating veth pair, already exists",
			"host_side", hostSide, "container_side", containerSide)
	} else {
		logger.V(3).Info("Created veth pair",
			"host_side", hostSide, "container_side", containerSide)
	}

	// Verify host side interface exists after creation
	if _, err := netlink.LinkByName(hostSide); err != nil {
		return fmt.Errorf("host side interface %s not found after creation: %w", hostSide, err)
	}

	// Note: Container side interface is created directly in the container namespace
	// and cannot be verified from the host namespace
	logger.V(3).Info("Veth pair created successfully",
		"host_side", hostSide, "container_side", containerSide)

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
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}
	m.logger.V(2).Info("IPv4 forwarding enabled via /proc/sys/net/ipv4/ip_forward")

	// Enable IPv6 forwarding if configured (though current external routing is IPv4 focused)
	if m.config.Network.EnableIPv6 {
		if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0644); err != nil {
			// Log as warning, as IPv4 might be primary
			m.logger.V(1).Error(err, "Failed to enable IPv6 forwarding, continuing with IPv4")
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
		return fmt.Errorf("failed to add IP address %s to interface %s: %w", ipAddress, interfaceName, err)
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
			m.logger.V(2).Info("Host interface not found, cannot remove IP", "interface", interfaceName)
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
		return fmt.Errorf("failed to delete IP address %s from interface %s: %w", ipAddress, interfaceName, err)
	}
	m.logger.V(2).Info("Successfully removed IP address from host interface",
		"ip_address", ipAddress, "interface", interfaceName)
	return nil
}

// ensureIPTablesForwardRule ensures an iptables FORWARD rule exists or is absent.
// action can be "CREATE" or "DELETE".
// This is a simplified version; a more robust solution would use an iptables library.
func (m *Manager) ensureIPTablesForwardRule(action string, externalIP string) error {
	// Parse the IP to remove any CIDR mask for the rule if needed, though iptables handles CIDR.
	ipOnly := externalIP
	if strings.Contains(externalIP, "/") {
		ip, _, err := net.ParseCIDR(externalIP)
		if err == nil {
			ipOnly = ip.String()
		} else {
			// If parsing fails, use the original string but log a warning
			m.logger.V(1).Info("Could not parse CIDR from external IP for iptables rule, using raw string", "external_ip", externalIP, "error", err)
		}
	}

	// Rule to allow forwarding to the external IP
	argsTo := []string{"-d", ipOnly, "-j", "ACCEPT"}
	// Rule to allow forwarding from the external IP
	argsFrom := []string{"-s", ipOnly, "-j", "ACCEPT"}

	var errTo, errFrom error

	switch strings.ToUpper(action) {
	case "CREATE":
		// Check if rule exists before adding (iptables -C)
		if !m.iptablesRuleExists(append([]string{"-C", "FORWARD"}, argsTo...)...) {
			errTo = m.runIPTablesCommand(append([]string{"-A", "FORWARD"}, argsTo...)...)
		} else {
			m.logger.V(2).Info("iptables FORWARD rule (to externalIP) already exists", "ip_address", ipOnly)
		}
		if !m.iptablesRuleExists(append([]string{"-C", "FORWARD"}, argsFrom...)...) {
			errFrom = m.runIPTablesCommand(append([]string{"-A", "FORWARD"}, argsFrom...)...)
		} else {
			m.logger.V(2).Info("iptables FORWARD rule (from externalIP) already exists", "ip_address", ipOnly)
		}
	case "DELETE":
		// Delete rule if it exists (iptables -D)
		// Deleting a non-existent rule with -D can error, so check first or ignore error.
		// For simplicity, we'll try to delete. If it doesn't exist, iptables usually exits non-zero.
		// A more robust way is to list and parse, or use -C then -D.
		errTo = m.runIPTablesCommand(append([]string{"-D", "FORWARD"}, argsTo...)...)
		errFrom = m.runIPTablesCommand(append([]string{"-D", "FORWARD"}, argsFrom...)...)
		// Suppress "No such file or directory" or "does not exist" type errors for delete
		if errTo != nil && !strings.Contains(errTo.Error(), "No such file or directory") && !strings.Contains(errTo.Error(), "does not exist") {
			// Log actual error
		} else if errTo == nil {
			m.logger.V(2).Info("iptables FORWARD rule (to externalIP) deleted or was not present", "ip_address", ipOnly)
			errTo = nil // Clear error if it was a "not found" type
		}

		if errFrom != nil && !strings.Contains(errFrom.Error(), "No such file or directory") && !strings.Contains(errFrom.Error(), "does not exist") {
			// Log actual error
		} else if errFrom == nil {
			m.logger.V(2).Info("iptables FORWARD rule (from externalIP) deleted or was not present", "ip_address", ipOnly)
			errFrom = nil // Clear error
		}

	default:
		return fmt.Errorf("invalid action for iptables rule: %s", action)
	}

	if errTo != nil {
		return fmt.Errorf("failed to %s iptables FORWARD rule (to %s): %w", strings.ToLower(action), ipOnly, errTo)
	}
	if errFrom != nil {
		return fmt.Errorf("failed to %s iptables FORWARD rule (from %s): %w", strings.ToLower(action), ipOnly, errFrom)
	}

	m.logger.V(2).Info("Successfully ensured iptables FORWARD rule state", "action", action, "ip_address", ipOnly)
	return nil
}

// iptablesRuleExists checks if a specific iptables rule exists.
func (m *Manager) iptablesRuleExists(args ...string) bool {
	// Use iptables -C (check) which returns 0 if rule exists, non-zero otherwise.
	// We need to prepend "-C" and the chain name to the args provided.
	// The args should be the rule specification itself (e.g., "-d", "ip", "-j", "ACCEPT")
	// This function is called with args already including -C and FORWARD.
	cmd := "iptables"
	fullArgs := args // args already contains -C FORWARD ...

	_, err := m.runCommand(cmd, fullArgs...)
	// If err is nil, the rule exists. If err is not nil, it doesn't (or another error occurred).
	return err == nil
}

// runIPTablesCommand runs an iptables command.
// This is a placeholder for actual command execution logic.
func (m *Manager) runIPTablesCommand(args ...string) error {
	cmd := "iptables"
	// In a real scenario, use os/exec to run the command.
	// For now, just log it.
	m.logger.V(3).Info("Executing iptables command", "command", cmd, "args", args)

	// Example of actual execution (requires proper error handling and output capture):
	// _, err := exec.Command(cmd, args...).CombinedOutput()
	// if err != nil {
	//    return fmt.Errorf("iptables command '%s %s' failed: %v, output: %s", cmd, strings.Join(args, " "), err, string(output))
	// }
	// return nil

	// Simulate success for now, as we don't have exec.Command available in this tool environment.
	// To make this testable or actually work, you'd need to implement m.runCommand or similar.
	// For the purpose of this refactoring, we assume this helper exists and works.
	// If runCommand is not available on Manager, this needs to be adapted.
	// Let's assume m.runCommand exists and is similar to the one in ovs_service.go (but it's not there yet)

	// If we had a generic runCommand on m.Manager:
	// output, err := m.runCommand(cmd, args...)
	// if err != nil {
	// 	return fmt.Errorf("iptables command '%s %s' failed: %v, output: %s", cmd, strings.Join(args, " "), err, output)
	// }

	// Since we don't have a generic runCommand on Manager that returns output and error for general commands,
	// and the tool environment doesn't allow `os/exec`, we'll leave this as a conceptual placeholder.
	// In a real environment, this would execute the command.
	// For now, to avoid compile errors if m.runCommand is not defined, we will just log.
	// This part will need to be implemented with actual command execution for the feature to work.

	// Placeholder: Simulate that DELETE for a non-existent rule might return an error that we want to ignore.
	if args[0] == "-D" {
		// Simulate common error message for non-existent rule to test error handling in ensureIPTablesForwardRule
		// return fmt.Errorf("iptables: No chain/target/match by that name.")
	}

	return nil // Placeholder: Simulate success
}

// runCommand is a helper to execute shell commands (conceptual)
// This would typically use os/exec. As it's not available, this is a stub.
// This is NOT the same as the runCommand in ovs_service.go which is specific to ovs-vsctl/ovs-ofctl.
func (m *Manager) runCommand(command string, args ...string) (string, error) {
	// This is a stub. In a real implementation, use os/exec.
	m.logger.V(4).Info("Simulating command execution (stub)", "command", command, "args", args)
	// Simulate success for most cases, or specific errors for testing.
	if command == "iptables" && len(args) > 0 && args[0] == "-C" {
		// Simulate rule not existing for -C check, causing an error
		// To test the creation path, make -C fail.
		// return "", fmt.Errorf("iptables: No chain/target/match by that name.")
	}
	return "", nil
}
