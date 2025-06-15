package manager

import (
	"context"
	"fmt"
	"net"
	"strconv"
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
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
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
	ovs          client.Client // Retain for general OVS client needs like connect, monitor, cache access if not covered by service
	ovsService   *ovsService   // Add ovsService field
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

	// Create Docker client with configured socket path
	dockerOpts := []dockerclient.Opt{
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	}

	// Use configured Docker socket path if specified
	if cfg.Docker.SocketPath != "" {
		dockerOpts = append(dockerOpts, dockerclient.WithHost("unix://"+cfg.Docker.SocketPath))
	}

	dockerClient, err := dockerclient.NewClientWithOpts(dockerOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	// Test Docker client connectivity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dockerInfo, err := dockerClient.Info(ctx)
	if err != nil {
		logger.Error(err, "Failed to connect to Docker daemon", "socketPath", cfg.Docker.SocketPath)
		return nil, fmt.Errorf("failed to connect to Docker daemon: %v", err)
	}
	logger.Info("Successfully connected to Docker daemon",
		"version", dockerInfo.ServerVersion,
		"platform", dockerInfo.OperatingSystem,
		"socketPath", cfg.Docker.SocketPath)

	// Create OVS database client with configurable database name
	clientDBModel, err := models.FullDatabaseModel()
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS schema: %v", err)
	}

	// Create a minimal logger for libovsdb that suppresses verbose cache updates
	// This will significantly reduce the chatty interface statistics logging
	ovsLibLogger := logger.WithName("libovsdb").V(0) // Only critical messages from libovsdb

	ovsClient, err := client.NewOVSDBClient(
		clientDBModel,
		client.WithEndpoint("unix:"+cfg.OVS.SocketPath),
		client.WithLogger(
			&ovsLibLogger,
		), // Configure libovsdb to use our logger with reduced verbosity
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS client: %v", err)
	}

	// Test OVS client connectivity
	err = ovsClient.Connect(ctx)
	if err != nil {
		logger.Error(err, "Failed to connect to OVS database", "socketPath", cfg.OVS.SocketPath)
		return nil, fmt.Errorf("failed to connect to OVS database: %v", err)
	}
	logger.Info("Successfully connected to OVS database", "socketPath", cfg.OVS.SocketPath)

	models.Schema() // This seems to be a global registration, keep it.

	// Initialize ovsService
	service := newOVSService(ovsClient, logger)

	return &Manager{
		dockerClient: dockerClient,
		ovs:          ovsClient, // Keep ovs client for now for connect/disconnect/monitor
		ovsService:   service,   // Assign new service
		logger:       logger,
		config:       cfg,
	}, nil
}

// Start begins monitoring Docker events and managing OVS ports.
func (m *Manager) Start(ctx context.Context) error {
	m.logger.V(3).Info("Starting OVS Port Manager...")

	// Connect to OVS database
	if err := m.ovs.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to OVS database: %v", err)
	}
	defer func() {
		m.ovs.Disconnect()
	}()

	// Set up monitoring to populate the cache
	_, err := m.ovs.Monitor(
		ctx,
		m.ovs.NewMonitor(
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
	if err := m.ovs.List(ctx, &l); err != nil {
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
	// Use ovsService to ensure the bridge exists
	return m.ovsService.ensureBridge(ctx, m.config.OVS.DefaultBridge, "default-bridge-uuid")
}

// processExistingContainers processes all running containers that have OVS labels.
// This method implements idempotent behavior - it will create missing ports and verify existing ones.
func (m *Manager) processExistingContainers(ctx context.Context) error {
	containers, err := m.dockerClient.ContainerList(ctx, container.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %v", err)
	}

	m.logger.V(1).Info("Processing existing containers for OVS configuration",
		"total_containers", len(containers))

	var processedCount, errorCount int
	for _, container := range containers {
		config := m.extractOVSConfig(container.ID, container.Labels)
		if config == nil {
			continue // Container doesn't have OVS labels
		}

		processedCount++
		m.logger.V(1).Info("Processing existing container",
			"container_id", config.ContainerID[:12],
			"ip_address", config.IPAddress,
			"bridge", config.Bridge)

		// Use the same AddPort method which now includes idempotency checks
		if err := m.addOVSPort(ctx, config); err != nil {
			errorCount++
			m.logger.Error(
				err,
				"Failed to configure OVS port for existing container",
				"container_id",
				config.ContainerID[:12],
				"interface", config.Interface,
			)
			// Continue processing other containers even if one fails
		} else {
			m.logger.V(2).Info("Successfully configured OVS port for existing container",
				"container_id", config.ContainerID[:12],
				"interface", config.Interface)
		}
	}

	successRate := float64(processedCount-errorCount) / float64(max(1, processedCount)) * 100
	m.logger.V(1).Info("Completed processing existing containers",
		"processed", processedCount,
		"errors", errorCount,
		"success_rate", fmt.Sprintf("%.1f%%", successRate))

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

// handleContainerStart handles container start events with restart detection.
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

	// Check if this is a restart by looking for existing ports
	// Use ovsService to find ports
	existingPorts, err := m.ovsService.findPortsForContainer(ctx, containerID)
	if err != nil {
		m.logger.V(1).
			Error(err, "Failed to check for existing ports via service", "container_id", containerID[:12])
	}

	if len(existingPorts) > 0 {
		m.logger.V(1).Info("Container restart detected, verifying port configuration",
			"container_id", containerID[:12],
			"existing_ports", len(existingPorts))

		// For restart, we use the AddPort method which now includes idempotency checks
		// It will verify existing configuration and only recreate if needed
	} else {
		m.logger.V(1).Info("Container started with OVS configuration",
			"container_id", containerID[:12],
			"ip_address", config.IPAddress,
			"bridge", config.Bridge)
	}

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
	// Find all ports for this container using external_ids via ovsService
	ports, err := m.ovsService.findPortsForContainer(ctx, containerID)
	if err != nil {
		// This error is critical as we can't identify ports to remove.
		return fmt.Errorf("failed to find ports for container via service: %v", err)
	}

	if len(ports) == 0 {
		m.logger.V(3).Info("No OVS ports found for container", "container_id", containerID[:12])
		return nil // No ports to remove, not an error.
	}

	// The original logic logged errors during removal of individual ports but continued.
	// We will maintain that behavior. If any operation fails, it's logged,
	// but the function will attempt to remove all identified ports and return nil.
	for _, portName := range ports {
		m.logger.V(1).Info("Removing OVS port",
			"container_id", containerID[:12],
			"port_name", portName)

		// Remove port from OVS via ovsService
		if errRmv := m.ovsService.removePortFromBridge(ctx, portName); errRmv != nil {
			m.logger.Error(
				errRmv,
				"Failed to remove port from OVS via service",
				"port_name",
				portName,
			)
			// Continue to the next port
		}

		// Delete the veth pair
		if errDel := m.deleteLinkByName(portName, m.logger); errDel != nil { // Pass logger
			m.logger.Error(errDel, "Failed to delete veth pair", "port_name", portName)
			// Continue to the next port
		}
	} // Closes for loop

	m.logger.V(3).Info("Completed OVS port cleanup", "container_id", containerID[:12])
	return nil // Reflects original behavior of not returning errors from the loop.
} // Closes function

// generatePortName generates a unique port name for a container.
func (m *Manager) generatePortName(containerID string) string {
	// Use first 12 characters of container ID as the port name
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

// isPortFullyConfigured checks if an existing port is fully configured with the expected settings.
func (m *Manager) isPortFullyConfigured(
	ctx context.Context,
	containerID, interfaceName string,
	opts *ContainerOVSConfig,
) (bool, error) {
	// Get container namespace file descriptor
	fd, cleanup, err := m.getContainerFd(ctx, containerID, m.logger) // Pass logger
	if err != nil {
		return false, fmt.Errorf("failed to get container fd: %w", err)
	}
	defer cleanup()

	// Create a netlink handle for the container namespace
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(fd))
	if err != nil {
		return false, fmt.Errorf("failed to create netlink handle for container namespace: %w", err)
	}
	defer nsHandle.Delete()

	// Check if the target interface exists in the container
	link, err := nsHandle.LinkByName(interfaceName)
	if err != nil {
		// Interface doesn't exist in container
		return false, nil
	}

	// Check if interface is up
	if link.Attrs().Flags&net.FlagUp == 0 {
		return false, nil
	}

	// Check IP address if specified
	if opts.IPAddress != "" {
		addrs, err := nsHandle.AddrList(link, 0) // 0 for all families
		if err != nil {
			return false, fmt.Errorf("failed to list addresses: %v", err)
		}

		expectedAddr, err := netlink.ParseAddr(opts.IPAddress)
		if err != nil {
			return false, fmt.Errorf("failed to parse expected IP: %v", err)
		}

		hasExpectedIP := false
		for _, addr := range addrs {
			if addr.IP.Equal(expectedAddr.IP) && addr.Mask.String() == expectedAddr.Mask.String() {
				hasExpectedIP = true
				break
			}
		}
		if !hasExpectedIP {
			return false, nil
		}
	}

	// Check MAC address if specified
	if opts.MACAddress != "" {
		expectedMAC, err := net.ParseMAC(opts.MACAddress)
		if err != nil {
			return false, fmt.Errorf("failed to parse expected MAC: %v", err)
		}
		if !macAddressesEqual(link.Attrs().HardwareAddr, expectedMAC) {
			return false, nil
		}
	}

	// Check MTU if specified
	if opts.MTU != "" {
		expectedMTU, err := strconv.Atoi(opts.MTU)
		if err != nil {
			return false, fmt.Errorf("failed to parse expected MTU: %v", err)
		}
		if link.Attrs().MTU != expectedMTU {
			return false, nil
		}
	}

	// Check default route if gateway is specified
	if opts.Gateway != "" {
		routes, err := nsHandle.RouteList(link, 0) // 0 for all families
		if err != nil {
			return false, fmt.Errorf("failed to list routes: %v", err)
		}

		expectedGW := net.ParseIP(opts.Gateway)
		if expectedGW == nil {
			return false, fmt.Errorf("invalid gateway IP: %s", opts.Gateway)
		}

		hasDefaultRoute := false
		for _, route := range routes {
			// Check for default route (0.0.0.0/0 or ::/0)
			if route.Dst == nil ||
				(route.Dst.IP.IsUnspecified() &&
					((route.Dst.IP.To4() != nil && route.Dst.Mask.String() == "00000000") ||
						(route.Dst.IP.To4() == nil && route.Dst.Mask.String() == "00000000000000000000000000000000"))) {
				if route.Gw != nil && route.Gw.Equal(expectedGW) {
					hasDefaultRoute = true
					break
				}
			}
		}
		if !hasDefaultRoute {
			return false, nil
		}
	}

	return true, nil
}

// cleanupExistingPort removes an existing port and its associated network interfaces.
func (m *Manager) cleanupExistingPort(
	ctx context.Context,
	portName, containerID string,
) (err error) { // Added ctx
	m.logger.V(2).Info("Cleaning up existing port",
		"port", portName,
		"container_id", containerID[:12])

	// Remove port from OVS bridge via ovsService
	if err = m.ovsService.removePortFromBridge(ctx, portName); err != nil {
		m.logger.V(1).
			Error(err, "Failed to remove port from OVS bridge during cleanup via service", "port", portName)
	}

	// Delete the veth pair (this will delete both sides)
	if err = m.deleteLinkByName(portName, m.logger); err != nil { // Pass logger
		m.logger.V(1).Error(err, "Failed to delete veth pair during cleanup", "port", portName)
	}

	return err
}

// ensurePortStateConsistent ensures that the port state is consistent between
// OVS database and kernel network interfaces.
func (m *Manager) ensurePortStateConsistent(
	ctx context.Context,
	portName, containerID string,
) error {
	// Check if port exists in OVS via ovsService
	ovsPort, err := m.ovsService.getOvsPortByName(ctx, portName)
	if err != nil {
		// This means there was an error querying, not necessarily that the port doesn't exist.
		return fmt.Errorf("failed to check OVS port %s via service: %v", portName, err)
	}
	ovsPortExists := ovsPort != nil

	// Check if host-side interface exists
	_, hostInterfaceErr := netlink.LinkByName(portName)
	hostInterfaceExists := hostInterfaceErr == nil

	// If OVS port exists but host interface doesn't, clean up OVS
	if ovsPortExists && !hostInterfaceExists {
		m.logger.V(1).Info("OVS port exists but host interface missing, cleaning up OVS",
			"port", portName, "container_id", containerID[:12])
		if err := m.ovsService.removePortFromBridge(ctx, portName); err != nil { // Use service
			return fmt.Errorf("failed to cleanup orphaned OVS port via service: %v", err)
		}
	}

	// If host interface exists but OVS port doesn't, clean up interface
	if !ovsPortExists && hostInterfaceExists {
		m.logger.V(1).Info("Host interface exists but OVS port missing, cleaning up interface",
			"port", portName, "container_id", containerID[:12])
		if err := m.deleteLinkByName(portName, m.logger); err != nil { // Pass logger
			return fmt.Errorf("failed to cleanup orphaned interface: %v", err)
		}
	}

	return nil
}

// createAndConfigurePort handles the atomic creation and configuration of a port.
func (m *Manager) createAndConfigurePort(
	ctx context.Context,
	bridge, hostSide, containerSide, containerID, interfaceName string,
	opts *ContainerOVSConfig,
) error {
	// Check if veth interfaces already exist and clean them up if needed
	if existingLink, err := netlink.LinkByName(hostSide); err == nil {
		m.logger.V(2).Info("Host side veth already exists, deleting before recreating",
			"interface", hostSide, "container_id", containerID[:12])
		if err := netlink.LinkDel(existingLink); err != nil {
			m.logger.V(1).
				Info("Failed to delete existing host side veth", "error", err, "interface", hostSide)
		}
	}
	// It's possible the container side was moved to a namespace that no longer exists if the container was removed abruptly.
	// Attempting to delete by name might fail if it's in a dead ns.
	// The creation logic should handle overwriting or creating fresh.

	// Get container namespace file descriptor
	fd, cleanupNetns, err := m.getContainerFd(ctx, containerID, m.logger) // Pass logger
	if err != nil {
		return fmt.Errorf("failed to get container netns fd: %w", err)
	}
	defer cleanupNetns()

	// Create veth pair
	if err := m.createVethPairWithNames(hostSide, containerSide, fd, m.logger); err != nil { // Pass logger
		return fmt.Errorf("failed to create veth pair: %w", err)
	}

	// Small delay to ensure veth pair is fully created before moving
	time.Sleep(time.Millisecond * 100)

	// Add host side to OVS bridge with external IDs via ovsService
	externalIDs := map[string]string{
		"container_id":    containerID,
		"container_iface": interfaceName,
	}
	if err := m.ovsService.addPortToBridge(ctx, bridge, hostSide, externalIDs); err != nil {
		if delErr := m.deleteLinkByName(hostSide, m.logger); delErr != nil { // Pass logger
			m.logger.V(1).
				Info("Failed to delete link during cleanup after addPortToBridge failure", "error", delErr, "link", hostSide)
		}
		// Also attempt to delete the peer, though it might be in the container ns
		if delPeerErr := m.deleteLinkByName(containerSide, m.logger); delPeerErr != nil {
			m.logger.V(1).
				Info("Failed to delete peer link during cleanup", "error", delPeerErr, "link", containerSide)
		}
		return fmt.Errorf("failed to add port to bridge via service: %w", err)
	}

	// Set host side up
	if err := m.setLinkUp(hostSide, m.logger); err != nil { // Pass logger
		if delErr := m.ovsService.removePortFromBridge(ctx, hostSide); delErr != nil { // Use service
			m.logger.V(1).
				Info("Failed to remove port from OVS bridge during cleanup via service", "error", delErr)
		}
		return fmt.Errorf("failed to set host side up: %w", err)
	}

	// Container side is already in the correct namespace (created with PeerNamespace)
	m.logger.V(3).Info("Container side interface already in target namespace",
		"container_side", containerSide,
		"container_id", containerID[:12],
	)

	// Configure interface in container (IP, MAC, MTU, Gateway)
	if err := m.configureInterfaceInContainer(ctx, containerID, containerSide, interfaceName, // Pass logger
		opts.IPAddress, opts.MACAddress, opts.MTU, opts.Gateway, m.logger); err != nil {
		if delErr := m.ovsService.removePortFromBridge(ctx, hostSide); delErr != nil { // Use service
			m.logger.V(1).
				Info("Failed to remove port from OVS bridge during cleanup via service", "error", delErr)
		}
		return fmt.Errorf("failed to configure interface in container: %w", err)
	}

	// Set VLAN if specified
	if opts.VLAN != "" {
		// Use the internal setVLAN which now calls ovsService
		if err := m.setVLAN(ctx, interfaceName, containerID, opts.VLAN); err != nil {
			m.logger.Error(
				err,
				"Failed to set VLAN via service, continuing without VLAN",
				"vlan",
				opts.VLAN,
			)
		}
	}

	return nil
}

// SetVLAN implements ovs-docker set-vlan functionality.
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
	// Get portName using ovsService
	portName, err := m.ovsService.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find port via service for VLAN setting: %v", err)
	}
	if portName == "" {
		return fmt.Errorf(
			"no port found for container %s and interface %s for VLAN setting",
			containerID[:12],
			interfaceName,
		)
	}

	// Parse VLAN as integer
	vlanInt, err := strconv.Atoi(vlan)
	if err != nil {
		return fmt.Errorf("invalid VLAN number: %v", err)
	}

	// Call ovsService to set VLAN
	if err := m.ovsService.setVLAN(ctx, portName, vlanInt); err != nil {
		return fmt.Errorf("ovsService failed to set VLAN: %w", err)
	}

	m.logger.Info("Successfully set VLAN via service",
		"container_id", containerID[:12],
		"interface", interfaceName,
		"port", portName,
		"vlan", vlan,
	)
	return nil
}

// AddPort implements ovs-docker add-port functionality with idempotency and retry logic.
func (m *Manager) AddPort(
	ctx context.Context,
	bridge, interfaceName, containerID string,
	opts *ContainerOVSConfig,
) error {
	// Check if port already exists in OVS and is fully configured
	// Use ovsService to get port name
	existingPortName, err := m.ovsService.getPortForContainerInterface(
		ctx,
		containerID,
		interfaceName,
	)
	if err != nil {
		return fmt.Errorf("failed to check existing port via service: %v", err)
	}

	if existingPortName != "" {
		// Check if the existing port is properly configured
		if configured, err := m.isPortFullyConfigured(ctx, containerID, interfaceName, opts); err != nil {
			m.logger.V(1).Error(err,
				"Failed to check if existing port is configured, will recreate",
				"container_id", containerID[:12],
				"interface", interfaceName,
				"existing_port", existingPortName)
			// Remove the incompletely configured port and recreate
			if cleanupErr := m.cleanupExistingPort(ctx, existingPortName, containerID); cleanupErr != nil { // Pass ctx
				m.logger.V(1).
					Error(cleanupErr, "Failed to cleanup existing port", "port", existingPortName)
			}
		} else if configured {
			m.logger.V(1).Info("Port already exists and is properly configured, skipping",
				"container_id", containerID[:12],
				"interface", interfaceName,
				"existing_port", existingPortName)
			return nil // Idempotent - port is already properly configured
		} else {
			m.logger.V(1).Info("Port exists but is not fully configured, recreating",
				"container_id", containerID[:12],
				"interface", interfaceName,
				"existing_port", existingPortName)
			// Remove the incompletely configured port and recreate
			if cleanupErr := m.cleanupExistingPort(ctx, existingPortName, containerID); cleanupErr != nil {
				m.logger.V(1).Error(cleanupErr, "Failed to cleanup existing port", "port", existingPortName)
			}
		}
	}

	// Ensure bridge exists (uses ovsService)
	if err := m.ensureBridgeExists(ctx, bridge); err != nil {
		return fmt.Errorf("failed to ensure bridge exists: %w", err)
	}

	// Generate port names
	portID := m.generatePortName(containerID)
	hostSide := portID + "_l"
	containerSide := portID + "_c"

	// Ensure port state is consistent before proceeding (uses ovsService)
	if err := m.ensurePortStateConsistent(ctx, hostSide, containerID); err != nil {
		m.logger.V(1).Error(err, "Failed to ensure consistent port state, continuing",
			"port", hostSide, "container_id", containerID[:12])
	}

	// Retry logic for veth creation and configuration
	const maxRetries = 3
	const retryDelay = time.Millisecond * 200

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := m.createAndConfigurePort(ctx, bridge, hostSide, containerSide,
			containerID, interfaceName, opts); err != nil {
			lastErr = err
			m.logger.V(1).Info("Port creation attempt failed, retrying",
				"attempt", attempt,
				"max_retries", maxRetries,
				"container_id", containerID[:12],
				"error", err)

			// Clean up any partial state before retrying
			// Pass ctx to cleanupExistingPort
			if cleanupErr := m.cleanupExistingPort(ctx, hostSide, containerID); cleanupErr != nil {
				m.logger.V(1).Error(cleanupErr, "Failed to cleanup after failed attempt",
					"attempt", attempt, "port", hostSide)
			}

			if attempt < maxRetries {
				time.Sleep(retryDelay * time.Duration(attempt)) // Exponential backoff
			}
			continue
		}

		// Success!
		lastErr = nil
		break
	}

	if lastErr != nil {
		return fmt.Errorf("failed to create port after %d attempts: %w", maxRetries, lastErr)
	}

	m.logger.Info("Successfully added OVS port",
		"container_id", containerID[:12],
		"bridge", bridge,
		"interface", interfaceName,
		"host_port", hostSide,
	)

	return nil
}

// DelPort implements ovs-docker del-port functionality.
func (m *Manager) DelPort(ctx context.Context, bridge, interfaceName, containerID string) error {
	// Use ovsService to get port name
	port, err := m.ovsService.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find port via service: %v", err)
	}
	if port == "" {
		return fmt.Errorf(
			"no port found for container %s and interface %s via service",
			containerID[:12],
			interfaceName,
		)
	}

	// Remove from OVS bridge via ovsService
	if err := m.ovsService.removePortFromBridge(ctx, port); err != nil {
		return fmt.Errorf("failed to remove port from bridge via service: %w", err)
	}

	// Delete the link
	if err := m.deleteLinkByName(port, m.logger); err != nil { // Pass logger
		return fmt.Errorf("failed to delete link: %w", err)
	}

	m.logger.Info("Successfully removed OVS port",
		"container_id", containerID[:12],
		"interface", interfaceName,
		"port", port,
	)

	return nil
}

// DelPorts implements ovs-docker del-ports functionality.
func (m *Manager) DelPorts(ctx context.Context, bridge, containerID string) error {
	// Use ovsService to find ports
	ports, err := m.ovsService.findPortsForContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container via service: %v", err)
	}

	if len(ports) == 0 {
		m.logger.V(1).Info("No ports found for container", "container_id", containerID[:12])
		return nil
	}

	for _, port := range ports {
		// Remove from OVS bridge via ovsService
		if err := m.ovsService.removePortFromBridge(ctx, port); err != nil {
			m.logger.Error(
				err,
				"Failed to remove port from bridge via service, continuing",
				"port",
				port,
			)
			continue
		}

		// Delete the link
		if err := m.deleteLinkByName(port, m.logger); err != nil { // Pass logger
			m.logger.Error(err, "Failed to delete link, continuing", "port", port)
		}
	}

	m.logger.Info("Successfully removed all OVS ports",
		"container_id", containerID[:12],
		"port_count", len(ports),
	)

	return nil
}

// ensureBridgeExists ensures the bridge exists, creating it if necessary.
func (m *Manager) ensureBridgeExists(ctx context.Context, bridgeName string) error {
	// Use ovsService to ensure the bridge exists
	// Ensure unique named UUID by incorporating the bridge name, which is good practice for named UUIDs if they need to be predictable yet distinct.
	return m.ovsService.ensureBridge(ctx, bridgeName, "manager-req-bridge-"+bridgeName)
}

// Retain macAddressesEqual as it's a general utility.
func macAddressesEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// End of file, ensure all old private OVS methods previously listed for removal
// (e.g., _ensureBridge, removePortFromOVSBridgeCommand, etc.) are now gone.
// The previous refactoring steps updated all callers to use ovsService or public methods.
// This edit ensures that if any of their definitions remained, they are now removed.
// The functions:
// - func (m *Manager) _ensureBridge(...) { ... }
// - func (m *Manager) removePortFromOVSBridgeCommand(...) { ... }
// - func (m *Manager) findPortsForContainer(...) { ... } // The original one
// - func (m *Manager) getPortForContainerInterface(...) { ... } // The original one
// - func (m *Manager) addPortToOVSBridge(...) { ... }
// - func (m *Manager) getRootUUID(...) { ... } // The one in Manager
// should no longer exist in this file.
