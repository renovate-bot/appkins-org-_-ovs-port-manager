package manager

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/appkins-org/ovs-port-manager/internal/config"
	"github.com/appkins-org/ovs-port-manager/internal/models"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/go-logr/logr"
	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	// OVSIPAddressLabel is the Docker label that contains the IP address to assign.
	OVSIPAddressLabel = "ovs.ip_address"
	// OVSBridgeLabel is the Docker label that specifies which bridge to connect to (optional, defaults to ovsbr0).
	OVSBridgeLabel = "ovs.bridge"
	// OVSGatewayLabel is the Docker label that specifies the gateway (optional).
	OVSGatewayLabel = "ovs.gateway"
	// OVSMTULabel is the Docker label that specifies the MTU (optional).
	OVSMTULabel = "ovs.mtu"
	// OVSMACAddressLabel is the Docker label that specifies the MAC address (optional).
	OVSMACAddressLabel = "ovs.mac_address"
	// OVSVLANLabel is the Docker label that specifies the VLAN tag (optional).
	OVSVLANLabel = "ovs.vlan"
	// OVSInterfaceLabel is the Docker label that specifies the interface name (optional, defaults to eth1).
	OVSInterfaceLabel = "ovs.interface"
	// InterfaceNameLimit is the maximum length for network interface names in Linux.
	InterfaceNameLimit = 15
)

// Manager manages OVS ports for Docker containers.
type Manager struct {
	dockerClient *dockerclient.Client
	ovsClient    client.Client
	logger       logr.Logger
	config       *config.Config
}

// ContainerOVSConfig holds the OVS configuration for a container.
type ContainerOVSConfig struct {
	ContainerID string
	IPAddress   string
	Bridge      string
	Gateway     string
	MTU         string
	MACAddress  string
	Interface   string
	VLAN        string
}

// New creates a new OVS port manager.
func New(logger logr.Logger) (*Manager, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %v", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	// Create Docker client
	dockerClient, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	// Create OVS database client with configurable database name
	clientDBModel, err := models.FullDatabaseModel()
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS schema: %v", err)
	}

	// Create a minimal logger for libovsdb that suppresses verbose cache updates
	// This will significantly reduce the chatty interface statistics logging
	ovsLogger := logger.WithName("libovsdb").V(0) // Only critical messages from libovsdb

	ovsClient, err := client.NewOVSDBClient(
		clientDBModel,
		client.WithEndpoint("unix:"+cfg.OVS.SocketPath),
		client.WithLogger(
			&ovsLogger,
		), // Configure libovsdb to use our logger with reduced verbosity
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS client: %v", err)
	}
	models.Schema()

	return &Manager{
		dockerClient: dockerClient,
		ovsClient:    ovsClient,
		logger:       logger,
		config:       cfg,
	}, nil
}

// Start begins monitoring Docker events and managing OVS ports.
func (m *Manager) Start(ctx context.Context) error {
	m.logger.V(3).Info("Starting OVS Port Manager...")

	// Connect to OVS database
	if err := m.ovsClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to OVS database: %v", err)
	}
	defer func() {
		m.ovsClient.Disconnect()
	}()

	// Set up monitoring to populate the cache
	_, err := m.ovsClient.Monitor(
		ctx,
		m.ovsClient.NewMonitor(
			client.WithTable(&models.OpenvSwitch{}),
			client.WithTable(&models.Bridge{}),
			client.WithTable(&models.Port{}),
			client.WithTable(&models.Interface{}),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to monitor OVS database: %v", err)
	}

	l := []models.OpenvSwitch{}
	if err := m.ovsClient.List(ctx, &l); err != nil {
		return fmt.Errorf("failed to list Open vSwitch: %v", err)
	}

	if len(l) == 0 {
		m.logger.Info(
			"No Open_vSwitch records found - this may indicate OVS is not fully initialized",
		)
		m.logger.Info("Continuing with bridge creation, but some operations may fail")
	} else {
		m.logger.V(1).Info("Connected to OVS database", "bridges", l[0].Bridges)
	}

	// Ensure default bridge exists
	if err := m.ensureDefaultBridge(ctx); err != nil {
		return fmt.Errorf("failed to ensure default bridge: %v", err)
	}

	// Process existing containers
	if err := m.processExistingContainers(ctx); err != nil {
		m.logger.V(1).Error(err, "Failed to process existing containers")
	}

	// Start listening for Docker events
	eventFilter := types.EventsOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "container"),
			filters.Arg("event", "start"),
			filters.Arg("event", "die"),
		),
	}

	eventsChan, errChan := m.dockerClient.Events(ctx, eventFilter)

	for {
		select {
		case event := <-eventsChan:
			if err := m.handleContainerEvent(ctx, event); err != nil {
				m.logger.Error(err, "Failed to handle container event")
			}
		case err := <-errChan:
			if err != nil {
				return fmt.Errorf("docker events error: %v", err)
			}
		case <-ctx.Done():
			m.logger.V(3).Info("Shutting down OVS Port Manager...")
			return nil
		}
	}
}

// ensureDefaultBridge creates the default OVS bridge if it doesn't exist.
func (m *Manager) ensureDefaultBridge(ctx context.Context) error {
	// Check if the bridge already exists
	var bridges []models.Bridge
	err := m.ovsClient.WhereCache(func(b *models.Bridge) bool {
		return b.Name == m.config.OVS.DefaultBridge
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to list bridges: %v", err)
	}

	if len(bridges) > 0 {
		m.logger.V(1).Info("Default bridge already exists", "bridge", m.config.OVS.DefaultBridge)
		return nil
	}

	m.logger.V(1).Info("Creating default bridge", "bridge", m.config.OVS.DefaultBridge)

	// Create bridge
	bridge := &models.Bridge{
		UUID:        "new-bridge", // Named UUID for transaction
		Name:        m.config.OVS.DefaultBridge,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	ops, err := m.ovsClient.Create(bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge operation: %v", err)
	}

	// Get the Open_vSwitch table to add this bridge to it
	var ovsList []models.OpenvSwitch
	err = m.ovsClient.List(ctx, &ovsList)
	if err != nil {
		return fmt.Errorf("failed to list Open_vSwitch: %v", err)
	}

	if len(ovsList) == 0 {
		return fmt.Errorf("no Open_vSwitch record found")
	}

	// Add bridge to Open_vSwitch bridges list using mutation
	ovsRow := &models.OpenvSwitch{UUID: ovsList[0].UUID}
	mutateOps, err := m.ovsClient.Where(ovsRow).Mutate(ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: "insert",
		Value:   []string{"new-bridge"}, // Reference named UUID
	})
	if err != nil {
		return fmt.Errorf("failed to create bridge mutation: %v", err)
	}

	// Combine operations
	allOps := append(ops, mutateOps...)

	// Execute the transaction
	_, err = m.ovsClient.Transact(ctx, allOps...)
	if err != nil {
		return fmt.Errorf("failed to create bridge %s: %v", m.config.OVS.DefaultBridge, err)
	}

	return nil
}

// processExistingContainers processes all running containers that have OVS labels.
func (m *Manager) processExistingContainers(ctx context.Context) error {
	containers, err := m.dockerClient.ContainerList(ctx, container.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %v", err)
	}

	for _, container := range containers {
		config := m.extractOVSConfig(container.ID, container.Labels)
		if config != nil {
			m.logger.V(1).Info("Processing existing container",
				"container_id", config.ContainerID[:12],
				"ip_address", config.IPAddress,
				"bridge", config.Bridge)

			if err := m.addOVSPort(ctx, config); err != nil {
				m.logger.Error(
					err,
					"Failed to add OVS port for existing container",
					"container_id",
					config.ContainerID[:12],
				)
			}
		}
	}

	return nil
}

// handleContainerEvent processes Docker container events.
func (m *Manager) handleContainerEvent(ctx context.Context, event events.Message) error {
	switch event.Action {
	case "start":
		return m.handleContainerStart(ctx, event.ID)
	case "die":
		return m.handleContainerStop(ctx, event.ID)
	default:
		return nil
	}
}

// handleContainerStart handles container start events.
func (m *Manager) handleContainerStart(ctx context.Context, containerID string) error {
	// Get container details
	container, err := m.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container %s: %v", containerID[:12], err)
	}

	config := m.extractOVSConfig(containerID, container.Config.Labels)
	if config == nil {
		// Container doesn't have OVS labels, ignore
		return nil
	}

	m.logger.V(1).Info("Container started with OVS configuration",
		"container_id", containerID[:12],
		"ip_address", config.IPAddress,
		"bridge", config.Bridge)

	return m.addOVSPort(ctx, config)
}

// handleContainerStop handles container stop events.
func (m *Manager) handleContainerStop(ctx context.Context, containerID string) error {
	m.logger.V(1).Info("Container stopped, cleaning up OVS ports", "container_id", containerID[:12])
	return m.removeOVSPort(ctx, containerID)
}

// extractOVSConfig extracts OVS configuration from container labels.
func (m *Manager) extractOVSConfig(
	containerID string,
	labels map[string]string,
) *ContainerOVSConfig {
	ipAddress, hasIP := labels[OVSIPAddressLabel]
	if !hasIP || ipAddress == "" {
		return nil
	}

	bridge := labels[OVSBridgeLabel]
	if bridge == "" {
		bridge = m.config.OVS.DefaultBridge
	}

	interfaceName := labels[OVSInterfaceLabel]
	if interfaceName == "" {
		interfaceName = m.config.OVS.DefaultInterface
	}

	return &ContainerOVSConfig{
		ContainerID: containerID,
		IPAddress:   ipAddress,
		Bridge:      bridge,
		Gateway:     labels[OVSGatewayLabel],
		MTU:         labels[OVSMTULabel],
		MACAddress:  labels[OVSMACAddressLabel],
		Interface:   interfaceName,
		VLAN:        labels[OVSVLANLabel],
	}
}

// addOVSPort adds an OVS port to a container (similar to ovs-docker add-port).
func (m *Manager) addOVSPort(ctx context.Context, config *ContainerOVSConfig) error {
	// Use the consolidated AddPort method
	return m.AddPort(ctx, config.Bridge, config.Interface, config.ContainerID, config)
}

// removeOVSPort removes OVS ports associated with a container
// This mirrors the ovs-docker del-port and del-ports behavior.
func (m *Manager) removeOVSPort(ctx context.Context, containerID string) error {
	// Find all ports for this container using external_ids
	// This mirrors: ovs-vsctl --data=bare --no-heading --columns=name find interface external_ids:container_id="$CONTAINER"
	ports, err := m.findPortsForContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container: %v", err)
	}

	if len(ports) == 0 {
		m.logger.V(3).Info("No OVS ports found for container", "container_id", containerID[:12])
		return nil
	}

	for _, portName := range ports {
		m.logger.V(1).Info("Removing OVS port (ovs-docker method)",
			"container_id", containerID[:12],
			"port_name", portName)

		// Remove port from OVS (mirroring: ovs-vsctl --if-exists del-port "$PORT")
		if err := m.removePortFromOVSBridgeCommand(portName); err != nil {
			m.logger.Error(err, "Failed to remove port from OVS", "port_name", portName)
		}

		// Delete the veth pair (mirroring: ip link delete "$PORT")
		// This will delete both sides of the veth pair
		if err := m.deleteLinkByName(portName); err != nil {
			m.logger.Error(err, "Failed to delete veth pair", "port_name", portName)
		}
	}

	m.logger.V(3).Info("Completed OVS port cleanup", "container_id", containerID[:12])
	return nil
}

func (m *Manager) getContainerSandboxKey(
	ctx context.Context,
	containerID string,
) (string, error) {
	container, err := m.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return "", fmt.Errorf("failed to inspect container %s: %v", containerID[:12], err)
	}

	if container.State.Pid == 0 {
		return "", fmt.Errorf("container %s is not running", containerID[:12])
	}

	if container.NetworkSettings.SandboxKey == "" {
		return "", fmt.Errorf("container %s has no sandbox ID", containerID[:12])
	}

	return container.NetworkSettings.SandboxKey, nil
}

// getContainerFd gets a file descriptor for the container's network namespace with proper cleanup.
// Returns fd, cleanup function, and error.
func (m *Manager) getContainerFd(
	ctx context.Context,
	containerID string,
) (int, func(), error) {
	netnsPath, err := m.getContainerSandboxKey(ctx, containerID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get container sandbox ID: %v", err)
	}

	// Use Docker's netns path via SandboxKey for more reliable access
	fd, err := unix.Open(netnsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to open netns %s: %v", netnsPath, err)
	}

	cleanup := func() {
		if err := unix.Close(fd); err != nil {
			// Log error but don't fail the operation - this is cleanup
			m.logger.V(1).Info("Failed to close container netns fd", "error", err)
		}
	}

	return fd, cleanup, nil
}

// getContainerNetNS gets a network namespace handle for the container with proper cleanup.
// Returns namespace handle, cleanup function, and error.
func (m *Manager) getContainerNetNS(
	ctx context.Context,
	containerID string,
) (netns.NsHandle, func(), error) {
	fd, cleanup, err := m.getContainerFd(ctx, containerID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get container netns fd: %v", err)
	}

	return netns.NsHandle(fd), cleanup, nil
}

// generatePortName generates a unique port name for a container.
func (m *Manager) generatePortName(containerID string) string {
	// Use first 12 characters of container ID as the port name, or the full ID if shorter
	// This provides exact matching for container operations and stays under the 15-char limit
	// Format: 1322aba3640c (12 chars) + _c (2 chars) = 14 chars total (under 15 limit)
	var portName string
	if len(containerID) >= 12 {
		portName = containerID[:12]
	} else {
		portName = containerID
	}

	// Validate that port name with suffix won't exceed kernel limit
	if len(portName+"_c") > InterfaceNameLimit {
		m.logger.V(1).Error(nil, "Generated port name may exceed kernel interface name limit",
			"portName", portName,
			"length", len(portName+"_c"),
			"limit", InterfaceNameLimit)
	}

	return portName
}

// setLinkUp sets a network interface up.
func (m *Manager) setLinkUp(interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set link %s up: %v", interfaceName, err)
	}

	return nil
}

// moveLinkToNetns moves a network interface to a different network namespace.
func (m *Manager) moveLinkToNetns(interfaceName, containerID string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	fd, cleanup, err := m.getContainerFd(context.Background(), containerID)
	if err != nil {
		return fmt.Errorf(
			"failed to get file descriptor for container %s: %v",
			containerID[:12],
			err,
		)
	}
	defer cleanup() // Ensure FD is properly closed

	if err := netlink.LinkSetNsFd(link, fd); err != nil {
		return fmt.Errorf("failed to move link %s to netns %d: %v", interfaceName, fd, err)
	}

	m.logger.V(3).Info("Moved interface to container namespace",
		"interface", interfaceName)

	return nil
}

// configureInterfaceInCurrentNs configures an interface in the current network namespace.
// This function assumes it's already running in the target namespace.
func (m *Manager) configureInterfaceInCurrentNs(
	oldName, newName, ipAddr, macAddr, mtu, gateway string,
) error {
	// Find the interface in the current namespace
	link, err := netlink.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("failed to find link %s in current namespace: %v", oldName, err)
	}

	// Rename interface if needed
	if newName != "" && oldName != newName {
		// Check if target interface name already exists
		if _, err := netlink.LinkByName(newName); err == nil {
			return fmt.Errorf("interface %s already exists, cannot rename %s",
				newName, oldName)
		}

		if err := netlink.LinkSetName(link, newName); err != nil {
			return fmt.Errorf("failed to rename interface %s to %s: %v", oldName, newName, err)
		}

		// Re-get the link with new name, with retry for timing issues
		var retryErr error
		for i := 0; i < 3; i++ {
			if link, retryErr = netlink.LinkByName(newName); retryErr == nil {
				break
			}
			m.logger.V(2).Info("Retrying to find renamed interface",
				"attempt", i+1, "oldName", oldName, "newName", newName, "error", retryErr)
			time.Sleep(time.Millisecond * 50) // Small delay
		}
		if retryErr != nil {
			return fmt.Errorf("failed to find renamed link %s (from %s): %v",
				newName, oldName, retryErr)
		}
	}

	// Set MAC address if provided
	if macAddr != "" {
		mac, err := net.ParseMAC(macAddr)
		if err != nil {
			return fmt.Errorf("invalid MAC address %s: %v", macAddr, err)
		}
		if err := netlink.LinkSetHardwareAddr(link, mac); err != nil {
			return fmt.Errorf("failed to set MAC address: %v", err)
		}
	}

	// Set MTU if provided
	if mtu != "" {
		mtuInt, err := strconv.Atoi(mtu)
		if err != nil {
			return fmt.Errorf("invalid MTU %s: %v", mtu, err)
		}
		if err := netlink.LinkSetMTU(link, mtuInt); err != nil {
			return fmt.Errorf("failed to set MTU: %v", err)
		}
	}

	// Configure IP address
	if ipAddr != "" {
		addr, err := netlink.ParseAddr(ipAddr)
		if err != nil {
			return fmt.Errorf("failed to parse IP address %s: %v", ipAddr, err)
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			// Check if address already exists
			if !strings.Contains(err.Error(), "file exists") {
				return fmt.Errorf("failed to add IP address: %v", err)
			}
		}
	}

	// Set interface up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface up: %v", err)
	}

	// Configure gateway if provided
	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return fmt.Errorf("invalid gateway IP %s", gateway)
		}

		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        gw,
		}

		if err := netlink.RouteAdd(route); err != nil {
			// Check if route already exists
			if !strings.Contains(err.Error(), "file exists") {
				return fmt.Errorf("failed to add gateway route: %v", err)
			}
		}
	}

	m.logger.V(3).Info("Configured interface in current namespace",
		"interface", newName,
		"ip", ipAddr,
		"mac", macAddr,
		"mtu", mtu,
		"gateway", gateway)

	return nil
}

// configureInterfaceInContainer configures an interface inside a container using Docker ID.
// This uses optimized file descriptor access via Docker SandboxKey.
func (m *Manager) configureInterfaceInContainer(
	ctx context.Context,
	containerID, oldName, newName, ipAddr, macAddr, mtu, gateway string,
) error {
	// Get container namespace with proper cleanup
	containerNs, containerCleanup, err := m.getContainerNetNS(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to get container netns: %v", err)
	}
	defer containerCleanup()

	// Get current (host) namespace
	hostNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host netns: %v", err)
	}
	defer func() {
		if err := hostNs.Close(); err != nil {
			m.logger.V(1).Info("Failed to close host namespace", "error", err)
		}
	}()

	// Switch to container namespace
	if err := netns.Set(containerNs); err != nil {
		return fmt.Errorf("failed to switch to container netns: %v", err)
	}

	// Ensure we switch back to host namespace
	defer func() {
		if err := netns.Set(hostNs); err != nil {
			m.logger.V(3).Error(err, "Failed to switch back to host namespace")
		}
	}()

	// Configure the interface within the container namespace
	if err := m.configureInterfaceInCurrentNs(oldName, newName, ipAddr, macAddr, mtu, gateway); err != nil {
		return err
	}

	m.logger.V(2).Info("Configured interface in container using optimized FD access",
		"container_id", containerID[:12],
		"old_name", oldName,
		"new_name", newName,
		"ip_address", ipAddr)

	return nil
}

// deleteLinkByName deletes a network interface by name.
func (m *Manager) deleteLinkByName(interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// Interface doesn't exist, consider it already cleaned up
		if strings.Contains(err.Error(), "Link not found") {
			return nil
		}
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %v", interfaceName, err)
	}

	m.logger.V(3).Info("Deleted network interface", "interface", interfaceName)
	return nil
}

// createVethPairWithNames creates a veth pair with specific names.
func (m *Manager) createVethPairWithNames(hostName, containerName string) error {
	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostName,
		},
		PeerName: containerName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("failed to create veth pair: %v", err)
		}
		m.logger.V(3).Info("Not creating veth pair, already exists",
			"host_side", hostName,
			"container_side", containerName,
		)
	} else {
		m.logger.V(3).Info("Created veth pair",
			"host_side", hostName,
			"container_side", containerName,
		)
	}

	return nil
}

// removePortFromOVSBridgeCommand removes a port from OVS bridge
// This mirrors: ovs-vsctl --if-exists del-port "$PORT".
func (m *Manager) removePortFromOVSBridgeCommand(portName string) error {
	// Find and delete the port
	var ports []models.Port
	err := m.ovsClient.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(context.Background(), &ports)
	if err != nil {
		return fmt.Errorf("failed to find port %s: %v", portName, err)
	}

	if len(ports) == 0 {
		// Port doesn't exist, which is fine (--if-exists behavior)
		return nil
	}

	// Delete the port
	for _, port := range ports {
		ops, err := m.ovsClient.Where(&port).Delete()
		if err != nil {
			return fmt.Errorf("failed to create delete operation: %v", err)
		}

		_, err = m.ovsClient.Transact(context.Background(), ops...)
		if err != nil {
			return fmt.Errorf("failed to delete port: %v", err)
		}
	}

	return nil
}

// findPortsForContainer finds all OVS ports associated with a container
// This mirrors: ovs-vsctl --data=bare --no-heading --columns=name find interface external_ids:container_id="$CONTAINER".
func (m *Manager) findPortsForContainer(ctx context.Context, containerID string) ([]string, error) {
	// Find interfaces by container_id external_id (this is how ovs-docker works)
	var interfaces []models.Interface
	err := m.ovsClient.WhereCache(func(i *models.Interface) bool {
		containerIDValue, exists := i.ExternalIDs["container_id"]
		return exists && containerIDValue == containerID
	}).List(ctx, &interfaces)
	if err != nil {
		return nil, fmt.Errorf("failed to find interfaces for container: %v", err)
	}

	// Return the interface names (which are the port names in our case)
	var portNames []string
	for _, iface := range interfaces {
		portNames = append(portNames, iface.Name)
	}

	m.logger.V(3).Info("Found ports for container",
		"container_id", containerID[:12],
		"port_count", len(portNames),
		"ports", portNames,
	)

	return portNames, nil
}

// getPortForContainerInterface finds a port for a container interface
// This mirrors the get_port_for_container_interface function from ovs-docker.
func (m *Manager) getPortForContainerInterface(
	ctx context.Context,
	containerID, interfaceName string,
) (string, error) {
	var interfaces []models.Interface
	err := m.ovsClient.WhereCache(func(i *models.Interface) bool {
		containerIDMatch := i.ExternalIDs["container_id"] == containerID
		interfaceMatch := i.ExternalIDs["container_iface"] == interfaceName
		return containerIDMatch && interfaceMatch
	}).List(ctx, &interfaces)
	if err != nil {
		return "", fmt.Errorf("failed to search for interfaces: %v", err)
	}

	if len(interfaces) == 0 {
		return "", nil // No existing port found
	}

	// Return the name of the first matching interface
	return interfaces[0].Name, nil
}

// ensureBridgeExists ensures the bridge exists, creating it if necessary
// This mirrors: ovs-vsctl br-exists "$BRIDGE" || ovs-vsctl add-br "$BRIDGE".
func (m *Manager) ensureBridgeExists(ctx context.Context, bridgeName string) error {
	// Check if bridge exists
	var bridges []models.Bridge

	err := m.ovsClient.List(ctx, &bridges)
	// err := m.ovsClient.WhereCache(func(b *models.Bridge) bool {
	// 	return b.Name == bridgeName
	// }).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to check if bridge exists: %v", err)
	}

	if len(bridges) > 0 {
		// Bridge already exists
		return nil
	}

	// Create the bridge
	bridge := &models.Bridge{
		UUID:        "new-bridge-exists", // Named UUID for transaction
		Name:        bridgeName,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	ops, err := m.ovsClient.Create(bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge operation: %v", err)
	}

	// Get the Open_vSwitch table to add this bridge to it
	var ovsList []models.OpenvSwitch
	err = m.ovsClient.List(ctx, &ovsList)
	if err != nil {
		return fmt.Errorf("failed to list Open_vSwitch: %v", err)
	}

	if len(ovsList) == 0 {
		return fmt.Errorf("no Open_vSwitch record found")
	}

	// Add bridge to Open_vSwitch bridges list using mutation
	ovsRow := &models.OpenvSwitch{UUID: ovsList[0].UUID}
	mutateOps, err := m.ovsClient.Where(ovsRow).Mutate(ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: "insert",
		Value:   []string{"new-bridge-exists"}, // Reference named UUID
	})
	if err != nil {
		return fmt.Errorf("failed to create bridge mutation: %v", err)
	}

	// Combine operations
	allOps := append(ops, mutateOps...)

	_, err = m.ovsClient.Transact(ctx, allOps...)
	if err != nil {
		return fmt.Errorf("failed to create bridge: %v", err)
	}

	m.logger.V(3).Info("Created OVS bridge", "bridge", bridgeName)
	return nil
}

// addPortToOVSBridge adds a port to an OVS bridge with optional external IDs
// This mirrors: ovs-vsctl --may-exist add-port "$BRIDGE" "$PORT".
func (m *Manager) addPortToOVSBridge(
	ctx context.Context,
	bridgeName, portName string,
	externalIDs ...map[string]string,
) error {
	// Find the bridge
	var bridges []models.Bridge
	err := m.ovsClient.WhereCache(func(b *models.Bridge) bool {
		return b.Name == bridgeName
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s: %v", bridgeName, err)
	}

	if len(bridges) == 0 {
		return fmt.Errorf("bridge %s not found", bridgeName)
	}

	bridge := &bridges[0]

	// Prepare external IDs
	interfaceExternalIDs := map[string]string{}
	if len(externalIDs) > 0 {
		interfaceExternalIDs = externalIDs[0]
	}

	// Create Interface record
	iface := &models.Interface{
		UUID:        "new-interface-add", // Named UUID for transaction
		Name:        portName,
		Type:        "",
		ExternalIDs: interfaceExternalIDs,
	}

	// Create Port record
	port := &models.Port{
		UUID:        "new-port-add", // Named UUID for transaction
		Name:        portName,
		Interfaces:  []string{"new-interface-add"}, // Link to interface named UUID
		ExternalIDs: map[string]string{},
	}

	// Build transaction operations
	operations := []ovsdb.Operation{}

	// Create interface operation
	interfaceOps, err := m.ovsClient.Create(iface)
	if err != nil {
		return fmt.Errorf("failed to create interface operation: %v", err)
	}
	operations = append(operations, interfaceOps...)

	// Create port operation
	portOps, err := m.ovsClient.Create(port)
	if err != nil {
		return fmt.Errorf("failed to create port operation: %v", err)
	}
	operations = append(operations, portOps...)

	// Add port to bridge operation
	bridge.Ports = append(bridge.Ports, "new-port-add") // Use named UUID
	bridgeOps, err := m.ovsClient.Where(bridge).Update(bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge update operation: %v", err)
	}
	operations = append(operations, bridgeOps...)

	// Execute transaction
	_, err = m.ovsClient.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	return nil
}

// Core ovs-docker functionality methods

// AddPort implements ovs-docker add-port functionality
// Mirrors: ovs-docker add-port BRIDGE INTERFACE CONTAINER [options].
func (m *Manager) AddPort(
	ctx context.Context,
	bridge, interfaceName, containerID string,
	opts *ContainerOVSConfig,
) error {
	// Check if port already exists
	existingPort, err := m.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to check existing port: %v", err)
	}
	if existingPort != "" {
		return fmt.Errorf(
			"port already attached for container %s and interface %s",
			containerID[:12],
			interfaceName,
		)
	}

	// Ensure bridge exists
	if err := m.ensureBridgeExists(ctx, bridge); err != nil {
		return fmt.Errorf("failed to ensure bridge exists: %v", err)
	}

	// Generate port names
	portID := m.generatePortName(containerID)
	hostSide := portID + "_l"
	containerSide := portID + "_c"

	// Create veth pair
	if err := m.createVethPairWithNames(hostSide, containerSide); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Add host side to OVS bridge with external IDs
	externalIDs := map[string]string{
		"container_id":    containerID,
		"container_iface": interfaceName,
	}
	if err := m.addPortToOVSBridge(ctx, bridge, hostSide, externalIDs); err != nil {
		if err := m.deleteLinkByName(hostSide); err != nil {
			m.logger.V(1).Info("Failed to delete link during cleanup", "error", err)
		}
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Set host side up
	if err := m.setLinkUp(hostSide); err != nil {
		if err := m.removePortFromOVSBridgeCommand(hostSide); err != nil {
			m.logger.V(1).Info("Failed to remove port from OVS bridge during cleanup", "error", err)
		}
		return fmt.Errorf("failed to set host side up: %v", err)
	}

	// Move container side to container namespace and configure
	if err := m.moveLinkToNetns(containerSide, containerID); err != nil {
		if err := m.removePortFromOVSBridgeCommand(hostSide); err != nil {
			m.logger.V(1).Info("Failed to remove port from OVS bridge during cleanup", "error", err)
		}
		return fmt.Errorf("failed to move link to container: %v", err)
	}

	// Configure interface in container (IP, MAC, MTU, Gateway)
	if err := m.configureInterfaceInContainer(ctx, containerID, containerSide, interfaceName,
		opts.IPAddress, opts.MACAddress, opts.MTU, opts.Gateway); err != nil {
		if err := m.removePortFromOVSBridgeCommand(hostSide); err != nil {
			m.logger.V(1).Info("Failed to remove port from OVS bridge during cleanup", "error", err)
		}
		return fmt.Errorf("failed to configure interface in container: %v", err)
	}

	// Set VLAN if specified
	if opts.VLAN != "" {
		if err := m.setVLAN(ctx, interfaceName, containerID, opts.VLAN); err != nil {
			m.logger.Error(err, "Failed to set VLAN, continuing without VLAN", "vlan", opts.VLAN)
		}
	}

	m.logger.Info("Successfully added OVS port",
		"container_id", containerID[:12],
		"bridge", bridge,
		"interface", interfaceName,
		"host_port", hostSide,
	)

	return nil
}

// DelPort implements ovs-docker del-port functionality
// Mirrors: ovs-docker del-port BRIDGE INTERFACE CONTAINER.
func (m *Manager) DelPort(ctx context.Context, bridge, interfaceName, containerID string) error {
	port, err := m.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find port: %v", err)
	}
	if port == "" {
		return fmt.Errorf(
			"no port found for container %s and interface %s",
			containerID[:12],
			interfaceName,
		)
	}

	// Remove from OVS bridge
	if err := m.removePortFromOVSBridgeCommand(port); err != nil {
		return fmt.Errorf("failed to remove port from bridge: %v", err)
	}

	// Delete the link
	if err := m.deleteLinkByName(port); err != nil {
		return fmt.Errorf("failed to delete link: %v", err)
	}

	m.logger.Info("Successfully removed OVS port",
		"container_id", containerID[:12],
		"interface", interfaceName,
		"port", port,
	)

	return nil
}

// DelPorts implements ovs-docker del-ports functionality
// Mirrors: ovs-docker del-ports BRIDGE CONTAINER.
func (m *Manager) DelPorts(ctx context.Context, bridge, containerID string) error {
	ports, err := m.findPortsForContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container: %v", err)
	}

	if len(ports) == 0 {
		m.logger.V(1).Info("No ports found for container", "container_id", containerID[:12])
		return nil
	}

	for _, port := range ports {
		// Remove from OVS bridge
		if err := m.removePortFromOVSBridgeCommand(port); err != nil {
			m.logger.Error(err, "Failed to remove port from bridge, continuing", "port", port)
			continue
		}

		// Delete the link
		if err := m.deleteLinkByName(port); err != nil {
			m.logger.Error(err, "Failed to delete link, continuing", "port", port)
		}
	}

	m.logger.Info("Successfully removed all OVS ports",
		"container_id", containerID[:12],
		"port_count", len(ports),
	)

	return nil
}

// SetVLAN implements ovs-docker set-vlan functionality
// Mirrors: ovs-docker set-vlan BRIDGE INTERFACE CONTAINER VLAN.
func (m *Manager) SetVLAN(
	ctx context.Context,
	bridge, interfaceName, containerID, vlan string,
) error {
	return m.setVLAN(ctx, interfaceName, containerID, vlan)
}

// setVLAN is the internal implementation of VLAN setting.
func (m *Manager) setVLAN(
	ctx context.Context,
	interfaceName, containerID, vlan string,
) error {
	port, err := m.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find port: %v", err)
	}
	if port == "" {
		return fmt.Errorf(
			"no port found for container %s and interface %s",
			containerID[:12],
			interfaceName,
		)
	}

	// Find the port in OVS and set VLAN tag
	var ports []models.Port
	err = m.ovsClient.WhereCache(func(p *models.Port) bool {
		return p.Name == port
	}).List(ctx, &ports)
	if err != nil {
		return fmt.Errorf("failed to find OVS port: %v", err)
	}

	if len(ports) == 0 {
		return fmt.Errorf("OVS port %s not found", port)
	}

	// Parse VLAN as integer
	vlanInt, err := strconv.Atoi(vlan)
	if err != nil {
		return fmt.Errorf("invalid VLAN number: %v", err)
	}

	// Update port with VLAN tag
	portRow := &ports[0]
	if portRow.Tag == nil {
		portRow.Tag = &vlanInt
	} else {
		*portRow.Tag = vlanInt
	}

	ops, err := m.ovsClient.Where(portRow).Update(portRow, &portRow.Tag)
	if err != nil {
		return fmt.Errorf("failed to create VLAN update operation: %v", err)
	}

	_, err = m.ovsClient.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to set VLAN: %v", err)
	}

	m.logger.Info("Successfully set VLAN",
		"container_id", containerID[:12],
		"interface", interfaceName,
		"port", port,
		"vlan", vlan,
	)

	return nil
}
