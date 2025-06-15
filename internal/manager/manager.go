package manager

import (
	"context"
	"fmt"
	"net"
	"slices"
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
	"github.com/google/uuid"
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

// OVS port manager namespace for UUID generation.
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

// Manager manages OVS ports for Docker containers.
type Manager struct {
	dockerClient *dockerclient.Client
	ovs          client.Client
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

	// Test OVS client connectivity
	err = ovsClient.Connect(ctx)
	if err != nil {
		logger.Error(err, "Failed to connect to OVS database", "socketPath", cfg.OVS.SocketPath)
		return nil, fmt.Errorf("failed to connect to OVS database: %v", err)
	}
	logger.Info("Successfully connected to OVS database", "socketPath", cfg.OVS.SocketPath)

	models.Schema()

	return &Manager{
		dockerClient: dockerClient,
		ovs:          ovsClient,
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
	// Check if the bridge already exists
	var bridges []models.Bridge
	err := m.ovs.WhereCache(func(b *models.Bridge) bool {
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

	// Get root UUID
	rootUUID, err := m.getRootUUID()
	if err != nil {
		return fmt.Errorf("failed to get root UUID: %v", err)
	}

	// Create bridge with proper UUID
	bridge := models.Bridge{
		UUID:        "new-bridge", // Named UUID for transaction
		Name:        m.config.OVS.DefaultBridge,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	// Create bridge insertion operation
	insertOp, err := m.ovs.Create(&bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge operation: %v", err)
	}

	// Create mutation to add bridge to Open_vSwitch table
	ovsRow := models.OpenvSwitch{
		UUID: rootUUID,
	}
	mutateOps, err := m.ovs.Where(&ovsRow).Mutate(&ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: "insert",
		Value:   []string{bridge.UUID}, // Reference the bridge UUID
	})
	if err != nil {
		return fmt.Errorf("failed to create bridge mutation: %v", err)
	}

	// Combine operations
	operations := append(insertOp, mutateOps...)

	// Execute the transaction
	reply, err := m.ovs.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to create bridge %s: %v", m.config.OVS.DefaultBridge, err)
	}

	// Check operation results
	if _, err := ovsdb.CheckOperationResults(reply, operations); err != nil {
		return fmt.Errorf("bridge creation failed: %v", err)
	}

	m.logger.V(1).Info("Bridge creation successful",
		"bridge", m.config.OVS.DefaultBridge,
		"uuid", reply[0].UUID.GoUUID)

	return nil
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
	existingPorts, err := m.findPortsForContainer(ctx, containerID)
	if err != nil {
		m.logger.V(1).
			Error(err, "Failed to check for existing ports", "container_id", containerID[:12])
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
	// Find all ports for this container using external_ids
	ports, err := m.findPortsForContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container: %v", err)
	}

	if len(ports) == 0 {
		m.logger.V(3).Info("No OVS ports found for container", "container_id", containerID[:12])
		return nil
	}

	for _, portName := range ports {
		m.logger.V(1).Info("Removing OVS port",
			"container_id", containerID[:12],
			"port_name", portName)

		// Remove port from OVS
		if err := m.removePortFromOVSBridgeCommand(portName); err != nil {
			m.logger.Error(err, "Failed to remove port from OVS", "port_name", portName)
		}

		// Delete the veth pair
		if err := m.deleteLinkByName(portName); err != nil {
			m.logger.Error(err, "Failed to delete veth pair", "port_name", portName)
		}
	}

	m.logger.V(3).Info("Completed OVS port cleanup", "container_id", containerID[:12])
	return nil
}

// getContainerSandboxKey gets the sandbox key for a container's network namespace.
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

// configureInterfaceInContainer configures an interface inside a container using Docker ID.
func (m *Manager) configureInterfaceInContainer(
	ctx context.Context,
	containerID, oldName, newName, ipAddr, macAddr, mtu, gateway string,
) error {
	// Get container namespace file descriptor
	fd, cleanup, err := m.getContainerFd(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to get container fd: %v", err)
	}
	defer cleanup()

	// Create a netlink handle for the container namespace
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(fd))
	if err != nil {
		return fmt.Errorf("failed to create netlink handle for container namespace: %v", err)
	}
	defer nsHandle.Delete()

	// Configure the interface within the container namespace using the handle
	if err := m.configureInterfaceWithHandle(nsHandle, oldName, newName, ipAddr, macAddr, mtu, gateway); err != nil {
		return err
	}

	m.logger.V(2).Info("Configured interface in container using modern netlink handle",
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
func (m *Manager) createVethPairWithNames(hostSide, containerSide string, fd int) error {
	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostSide,
		},
		PeerName:      containerSide,
		PeerNamespace: netlink.NsFd(fd),
	}

	if err := netlink.LinkAdd(veth); err != nil {
		if !strings.Contains(err.Error(), "file exists") {
			return fmt.Errorf("failed to create veth pair: %v", err)
		}
		m.logger.V(3).Info("Not creating veth pair, already exists",
			"host_side", hostSide,
			"container_side", containerSide,
		)
	} else {
		m.logger.V(3).Info("Created veth pair",
			"host_side", hostSide,
			"container_side", containerSide,
		)
	}

	// Verify host side interface exists after creation
	if _, err := netlink.LinkByName(hostSide); err != nil {
		return fmt.Errorf("host side interface %s not found after creation: %v", hostSide, err)
	}

	// Note: Container side interface is created directly in the container namespace
	// and cannot be verified from the host namespace
	m.logger.V(3).Info("Veth pair created successfully",
		"host_side", hostSide,
		"container_side", containerSide,
	)

	return nil
}

// removePortFromOVSBridgeCommand removes a port from OVS bridge.
func (m *Manager) removePortFromOVSBridgeCommand(portName string) error {
	ctx := context.Background()
	m.logger.V(2).Info("Removing port from OVS bridge", "port", portName)

	// Find the port
	var ports []models.Port
	err := m.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &ports)
	if err != nil {
		return fmt.Errorf("failed to find port %s: %v", portName, err)
	}

	if len(ports) == 0 {
		// Port doesn't exist, which is fine (--if-exists behavior)
		m.logger.V(1).Info("Port does not exist, nothing to remove", "port", portName)
		return nil
	}

	port := &ports[0]

	// Find which bridge contains this port
	var bridges []models.Bridge
	err = m.ovs.WhereCache(func(b *models.Bridge) bool {
		return slices.Contains(b.Ports, port.UUID)
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge containing port %s: %v", portName, err)
	}

	// Build transaction operations
	operations := []ovsdb.Operation{}

	// If we found a bridge containing this port, remove it from the bridge first
	if len(bridges) > 0 {
		bridge := &bridges[0]

		// Mutate the bridge to remove the port using the correct OVSDB mutation pattern
		mutateOp := ovsdb.Operation{
			Op:    "mutate",
			Table: "Bridge",
			Where: []ovsdb.Condition{{
				Column:   "_uuid",
				Function: "==",
				Value:    ovsdb.UUID{GoUUID: bridge.UUID},
			}},
			Mutations: []ovsdb.Mutation{{
				Column:  "ports",
				Mutator: "delete",
				Value: ovsdb.OvsSet{
					GoSet: []any{
						ovsdb.UUID{GoUUID: port.UUID},
					},
				},
			}},
		}
		operations = append(operations, mutateOp)
	}

	// Delete the port and its interfaces
	deleteOps, err := m.ovs.Where(port).Delete()
	if err != nil {
		return fmt.Errorf("failed to create delete operation: %v", err)
	}
	operations = append(operations, deleteOps...)

	// Execute transaction
	results, err := m.ovs.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to remove port from bridge: %v", err)
	}

	m.logger.V(2).Info("Successfully removed port from OVS bridge",
		"port", portName,
		"transactionResults", len(results))

	return nil
}

// findPortsForContainer finds all OVS ports associated with a container.
func (m *Manager) findPortsForContainer(ctx context.Context, containerID string) ([]string, error) {
	// Find interfaces by container_id external_id
	var interfaces []models.Interface
	err := m.ovs.WhereCache(func(i *models.Interface) bool {
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

// getPortForContainerInterface finds a port for a container interface.
func (m *Manager) getPortForContainerInterface(
	ctx context.Context,
	containerID, interfaceName string,
) (string, error) {
	var interfaces []models.Interface
	err := m.ovs.WhereCache(func(i *models.Interface) bool {
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

// ensureBridgeExists ensures the bridge exists, creating it if necessary.
func (m *Manager) ensureBridgeExists(ctx context.Context, bridgeName string) error {
	// Check if bridge exists
	var bridges []models.Bridge
	err := m.ovs.WhereCache(func(b *models.Bridge) bool {
		return b.Name == bridgeName
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to check if bridge exists: %v", err)
	}

	if len(bridges) > 0 {
		// Bridge already exists
		return nil
	}

	// Get root UUID
	rootUUID, err := m.getRootUUID()
	if err != nil {
		return fmt.Errorf("failed to get root UUID: %v", err)
	}

	// Create the bridge
	bridge := models.Bridge{
		UUID:        "new-bridge-exists", // Named UUID for transaction
		Name:        bridgeName,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	// Create bridge insertion operation
	insertOp, err := m.ovs.Create(&bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge operation: %v", err)
	}

	// Create mutation to add bridge to Open_vSwitch table
	ovsRow := models.OpenvSwitch{
		UUID: rootUUID,
	}
	mutateOps, err := m.ovs.Where(&ovsRow).Mutate(&ovsRow, model.Mutation{
		Field:   &ovsRow.Bridges,
		Mutator: "insert",
		Value:   []string{bridge.UUID}, // Reference the bridge UUID
	})
	if err != nil {
		return fmt.Errorf("failed to create bridge mutation: %v", err)
	}

	// Combine operations
	operations := append(insertOp, mutateOps...)

	// Execute the transaction
	reply, err := m.ovs.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to create bridge: %v", err)
	}

	// Check operation results
	if _, err := ovsdb.CheckOperationResults(reply, operations); err != nil {
		return fmt.Errorf("bridge creation failed: %v", err)
	}

	m.logger.V(3).Info("Created OVS bridge", "bridge", bridgeName,
		"uuid", reply[0].UUID.GoUUID)
	return nil
}

// addPortToOVSBridge adds a port to an OVS bridge with external IDs.
func (m *Manager) addPortToOVSBridge(
	ctx context.Context,
	bridgeName, portName string,
	externalIDs ...map[string]string,
) error {
	m.logger.V(2).Info("Adding port to OVS bridge", "bridge", bridgeName, "port", portName)

	// Check if port already exists on the bridge
	var existingPortsOnBridge []models.Port
	err := m.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &existingPortsOnBridge)
	if err != nil {
		return fmt.Errorf("failed to check existing ports: %v", err)
	}

	if len(existingPortsOnBridge) > 0 {
		m.logger.V(1).Info("Port already exists on bridge", "bridge", bridgeName, "port", portName)
		return nil
	}

	// Find the bridge
	var bridges []models.Bridge
	err = m.ovs.WhereCache(func(b *models.Bridge) bool {
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

	// Build transaction operations
	operations := []ovsdb.Operation{}

	// First, ensure the interface exists with correct external_ids
	var interfaceUUID string
	var existingInterfaces []models.Interface
	err = m.ovs.WhereCache(func(i *models.Interface) bool {
		return i.Name == portName
	}).List(ctx, &existingInterfaces)
	if err != nil {
		return fmt.Errorf("failed to check existing interfaces: %v", err)
	}

	interfaceExists := len(existingInterfaces) > 0
	if interfaceExists {
		// Interface already exists, use existing UUID
		existingInterface := &existingInterfaces[0]
		interfaceUUID = existingInterface.UUID

		// Update external IDs if needed
		if len(interfaceExternalIDs) > 0 {
			needsUpdate := false
			updatedExternalIDs := make(map[string]string)
			for k, v := range existingInterface.ExternalIDs {
				updatedExternalIDs[k] = v
			}
			for k, v := range interfaceExternalIDs {
				if existingInterface.ExternalIDs[k] != v {
					needsUpdate = true
				}
				updatedExternalIDs[k] = v
			}

			if needsUpdate {
				existingInterface.ExternalIDs = updatedExternalIDs
				if ops, err := m.ovs.Where(existingInterface).Update(existingInterface, &existingInterface.ExternalIDs); err != nil {
					return fmt.Errorf("failed to update interface external IDs: %v", err)
				} else {
					operations = append(operations, ops...)
				}
			}
		}

		m.logger.V(2).Info("Using existing interface", "interface", portName, "uuid", interfaceUUID)
	} else {
		// Create new Interface record with deterministic UUID
		interfaceUUID = "iface"
		iface := &models.Interface{
			UUID:        interfaceUUID,
			Name:        portName,
			Type:        "",
			ExternalIDs: interfaceExternalIDs,
		}

		// Create interface operation
		if ops, err := m.ovs.Create(iface); err != nil {
			return fmt.Errorf("failed to create interface operation: %v", err)
		} else {
			operations = append(operations, ops...)
		}

		m.logger.V(2).Info("Creating new interface", "interface", portName, "namedUUID", interfaceUUID)
	}

	// Then, ensure the port exists and references the interface
	var portUUID string
	var existingPorts []models.Port
	err = m.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &existingPorts)
	if err != nil {
		return fmt.Errorf("failed to check existing ports: %v", err)
	}

	portExists := len(existingPorts) > 0
	if portExists {
		// Port already exists, use existing UUID and check if interface reference is correct
		existingPort := &existingPorts[0]
		portUUID = existingPort.UUID

		// If we're creating a new interface, update the port to reference it
		if !interfaceExists {
			existingPort.Interfaces = []string{interfaceUUID}
			if ops, err := m.ovs.Where(existingPort).Update(existingPort, &existingPort.Interfaces); err != nil {
				return fmt.Errorf("failed to update port interfaces: %v", err)
			} else {
				operations = append(operations, ops...)
			}
		}

		m.logger.V(2).Info("Using existing port", "port", portName, "uuid", portUUID)
	} else {
		// Create new Port record with deterministic UUID
		portUUID = "ovsport"
		port := &models.Port{
			UUID:        portUUID,
			Name:        portName,
			Interfaces:  []string{interfaceUUID}, // Reference interface UUID (may be named UUID)
			ExternalIDs: map[string]string{},
		}

		// Create port operation
		if ops, err := m.ovs.Create(port); err != nil {
			return fmt.Errorf("failed to create port operation: %v", err)
		} else {
			operations = append(operations, ops...)
		}

		m.logger.V(2).Info("Creating new port", "port", portName, "namedUUID", portUUID)
	}

	// Finally, add the port to the bridge if it's not already there
	var bridgePorts []string
	bridgePorts = append(bridgePorts, bridge.Ports...)

	// Check if port is already in bridge (by UUID for existing ports, by named UUID for new ports)
	portAlreadyInBridge := false
	for _, existingPortRef := range bridgePorts {
		if portExists && existingPortRef == portUUID {
			portAlreadyInBridge = true
			break
		}
	}

	if !portAlreadyInBridge {
		// Add port to bridge using UUID reference
		if ops, err := m.ovs.Where(bridge).Mutate(
			bridge,
			model.Mutation{
				Field:   &bridge.Ports,
				Mutator: ovsdb.MutateOperationInsert,
				Value:   []string{portUUID},
			}); err == nil {
			operations = append(operations, ops...)
		} else {
			return fmt.Errorf("failed to create bridge mutation: %v", err)
		}
	}

	// Log transaction details before execution
	m.logger.V(2).Info("Executing OVSDB transaction",
		"bridge", bridgeName,
		"port", portName,
		"operationCount", len(operations))

	for i, op := range operations {
		m.logger.V(3).Info("OVSDB operation",
			"index", i,
			"op", op.Op,
			"table", op.Table,
			"where", len(op.Where))
	}

	// Execute transaction
	results, err := m.ovs.Transact(ctx, operations...)
	if err != nil {
		m.logger.Error(err, "OVS port update transaction failed",
			"bridge", bridgeName,
			"port", portName,
			"transactionResults", len(results))
		return fmt.Errorf("OVS transaction failed: %v", err)
	}
	if _, err := ovsdb.CheckOperationResults(results, operations); err != nil {
		m.logger.Error(err, "OVS transaction failed - detailed operation results",
			"bridge", bridgeName,
			"port", portName,
			"operationCount", len(operations),
			"resultCount", len(results))

		// Log details for each operation result
		for i, result := range results {
			if result.Error != "" {
				m.logger.Error(nil, "OVSDB operation failed",
					"operationIndex", i,
					"error", result.Error,
					"details", result.Details)
			} else {
				m.logger.V(3).Info("OVSDB operation succeeded",
					"operationIndex", i,
					"rowCount", result.Count)
			}
		}

		return fmt.Errorf("OVS transaction failed: %v", err)
	}

	m.logger.V(2).Info("Successfully added port to OVS bridge",
		"bridge", bridgeName,
		"port", portName,
		"transactionResults", len(results))

	return nil
}

// isPortFullyConfigured checks if an existing port is fully configured with the expected settings.
func (m *Manager) isPortFullyConfigured(
	ctx context.Context,
	containerID, interfaceName string,
	opts *ContainerOVSConfig,
) (bool, error) {
	// Get container namespace file descriptor
	fd, cleanup, err := m.getContainerFd(ctx, containerID)
	if err != nil {
		return false, fmt.Errorf("failed to get container fd: %v", err)
	}
	defer cleanup()

	// Create a netlink handle for the container namespace
	nsHandle, err := netlink.NewHandleAt(netns.NsHandle(fd))
	if err != nil {
		return false, fmt.Errorf("failed to create netlink handle for container namespace: %v", err)
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
func (m *Manager) cleanupExistingPort(portName, containerID string) (err error) {
	m.logger.V(2).Info("Cleaning up existing port",
		"port", portName,
		"container_id", containerID[:12])

	// Remove port from OVS bridge
	if err = m.removePortFromOVSBridgeCommand(portName); err != nil {
		m.logger.V(1).
			Error(err, "Failed to remove port from OVS bridge during cleanup", "port", portName)
	}

	// Delete the veth pair (this will delete both sides)
	if err = m.deleteLinkByName(portName); err != nil {
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
	// Check if port exists in OVS
	var ports []models.Port
	err := m.ovs.WhereCache(func(p *models.Port) bool {
		return p.Name == portName
	}).List(ctx, &ports)
	if err != nil {
		return fmt.Errorf("failed to check OVS port: %v", err)
	}

	ovsPortExists := len(ports) > 0

	// Check if host-side interface exists
	_, hostInterfaceErr := netlink.LinkByName(portName)
	hostInterfaceExists := hostInterfaceErr == nil

	// If OVS port exists but host interface doesn't, clean up OVS
	if ovsPortExists && !hostInterfaceExists {
		m.logger.V(1).Info("OVS port exists but host interface missing, cleaning up OVS",
			"port", portName, "container_id", containerID[:12])
		if err := m.removePortFromOVSBridgeCommand(portName); err != nil {
			return fmt.Errorf("failed to cleanup orphaned OVS port: %v", err)
		}
	}

	// If host interface exists but OVS port doesn't, clean up interface
	if !ovsPortExists && hostInterfaceExists {
		m.logger.V(1).Info("Host interface exists but OVS port missing, cleaning up interface",
			"port", portName, "container_id", containerID[:12])
		if err := m.deleteLinkByName(portName); err != nil {
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
			m.logger.V(1).Info("Failed to delete existing host side veth", "error", err)
		}
	}

	if existingLink, err := netlink.LinkByName(containerSide); err == nil {
		m.logger.V(2).Info("Container side veth already exists, deleting before recreating",
			"interface", containerSide, "container_id", containerID[:12])
		if err := netlink.LinkDel(existingLink); err != nil {
			m.logger.V(1).Info("Failed to delete existing container side veth", "error", err)
		}
	}

	fd, _, err := m.getContainerFd(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to get container netns fd: %v", err)
	}

	// Create veth pair
	if err := m.createVethPairWithNames(hostSide, containerSide, fd); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Small delay to ensure veth pair is fully created before moving
	time.Sleep(time.Millisecond * 100)

	// Add host side to OVS bridge with external IDs
	externalIDs := map[string]string{
		"container_id":    containerID,
		"container_iface": interfaceName,
	}
	if err := m.addPortToOVSBridge(ctx, bridge, hostSide, externalIDs); err != nil {
		if delErr := m.deleteLinkByName(hostSide); delErr != nil {
			m.logger.V(1).Info("Failed to delete link during cleanup", "error", delErr)
		}
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Set host side up
	if err := m.setLinkUp(hostSide); err != nil {
		if delErr := m.removePortFromOVSBridgeCommand(hostSide); delErr != nil {
			m.logger.V(1).
				Info("Failed to remove port from OVS bridge during cleanup", "error", delErr)
		}
		return fmt.Errorf("failed to set host side up: %v", err)
	}

	// Container side is already in the correct namespace (created with PeerNamespace)
	m.logger.V(3).Info("Container side interface already in target namespace",
		"container_side", containerSide,
		"container_id", containerID[:12],
	)

	// Configure interface in container (IP, MAC, MTU, Gateway)
	if err := m.configureInterfaceInContainer(ctx, containerID, containerSide, interfaceName,
		opts.IPAddress, opts.MACAddress, opts.MTU, opts.Gateway); err != nil {
		if delErr := m.removePortFromOVSBridgeCommand(hostSide); delErr != nil {
			m.logger.V(1).
				Info("Failed to remove port from OVS bridge during cleanup", "error", delErr)
		}
		return fmt.Errorf("failed to configure interface in container: %v", err)
	}

	// Set VLAN if specified
	if opts.VLAN != "" {
		if err := m.setVLAN(ctx, interfaceName, containerID, opts.VLAN); err != nil {
			m.logger.Error(err, "Failed to set VLAN, continuing without VLAN", "vlan", opts.VLAN)
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
	err = m.ovs.WhereCache(func(p *models.Port) bool {
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

	ops, err := m.ovs.Where(portRow).Update(portRow, &portRow.Tag)
	if err != nil {
		return fmt.Errorf("failed to create VLAN update operation: %v", err)
	}

	_, err = m.ovs.Transact(ctx, ops...)
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

// AddPort implements ovs-docker add-port functionality with idempotency and retry logic.
func (m *Manager) AddPort(
	ctx context.Context,
	bridge, interfaceName, containerID string,
	opts *ContainerOVSConfig,
) error {
	// Check if port already exists in OVS and is fully configured
	existingPort, err := m.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to check existing port: %v", err)
	}
	if existingPort != "" {
		// Check if the existing port is properly configured
		if configured, err := m.isPortFullyConfigured(ctx, containerID, interfaceName, opts); err != nil {
			m.logger.V(1).Error(err,
				"Failed to check if existing port is configured, will recreate",
				"container_id", containerID[:12],
				"interface", interfaceName,
				"existing_port", existingPort)
			// Remove the incompletely configured port and recreate
			if cleanupErr := m.cleanupExistingPort(existingPort, containerID); cleanupErr != nil {
				m.logger.V(1).
					Error(cleanupErr, "Failed to cleanup existing port", "port", existingPort)
			}
		} else if configured {
			m.logger.V(1).Info("Port already exists and is properly configured, skipping",
				"container_id", containerID[:12],
				"interface", interfaceName,
				"existing_port", existingPort)
			return nil // Idempotent - port is already properly configured
		} else {
			m.logger.V(1).Info("Port exists but is not fully configured, recreating",
				"container_id", containerID[:12],
				"interface", interfaceName,
				"existing_port", existingPort)
			// Remove the incompletely configured port and recreate
			if cleanupErr := m.cleanupExistingPort(existingPort, containerID); cleanupErr != nil {
				m.logger.V(1).Error(cleanupErr, "Failed to cleanup existing port", "port", existingPort)
			}
		}
	}

	// Ensure bridge exists
	if err := m.ensureBridgeExists(ctx, bridge); err != nil {
		return fmt.Errorf("failed to ensure bridge exists: %v", err)
	}

	// Generate port names
	portID := m.generatePortName(containerID)
	hostSide := portID + "_l"
	containerSide := portID + "_c"

	// Ensure port state is consistent before proceeding
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
			if cleanupErr := m.cleanupExistingPort(hostSide, containerID); cleanupErr != nil {
				m.logger.V(1).Error(cleanupErr, "Failed to cleanup after failed attempt",
					"attempt", attempt)
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
		return fmt.Errorf("failed to create port after %d attempts: %v", maxRetries, lastErr)
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

// DelPorts implements ovs-docker del-ports functionality.
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

// macAddressesEqual compares two MAC addresses for equality.
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

// getRootUUID retrieves the root UUID from the Open_vSwitch table.
func (m *Manager) getRootUUID() (string, error) {
	var rootUUID string
	for uuid := range m.ovs.Cache().Table("Open_vSwitch").Rows() {
		rootUUID = uuid
		break // Take the first (and typically only) UUID
	}
	if rootUUID == "" {
		return "", fmt.Errorf("no Open_vSwitch root UUID found")
	}
	return rootUUID, nil
}

// addARPNeighbor adds an ARP neighbor entry for the specified interface.
func (m *Manager) addARPNeighbor(link netlink.Link, neighborIP, neighborMAC string) error {
	if neighborIP == "" || neighborMAC == "" {
		return nil // Skip if either IP or MAC is empty
	}

	// Parse the neighbor IP address
	ip := net.ParseIP(neighborIP)
	if ip == nil {
		return fmt.Errorf("invalid neighbor IP address: %s", neighborIP)
	}

	// Parse the neighbor MAC address
	mac, err := net.ParseMAC(neighborMAC)
	if err != nil {
		return fmt.Errorf("invalid neighbor MAC address %s: %v", neighborMAC, err)
	}

	// Create the neighbor entry
	neighbor := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        0x02, // NUD_PERMANENT - permanent ARP entry
		IP:           ip,
		HardwareAddr: mac,
	}

	// Add the neighbor
	if err := netlink.NeighAdd(neighbor); err != nil {
		// Check if neighbor already exists
		if strings.Contains(err.Error(), "file exists") {
			m.logger.V(2).Info("ARP neighbor already exists", "ip", neighborIP, "mac", neighborMAC)
			return nil
		}
		return fmt.Errorf("failed to add ARP neighbor %s -> %s: %v", neighborIP, neighborMAC, err)
	}

	m.logger.V(2).
		Info("Added ARP neighbor", "ip", neighborIP, "mac", neighborMAC, "interface", link.Attrs().Name)
	return nil
}

// addARPNeighborWithHandle adds a static ARP neighbor entry using a specific netlink handle.
func (m *Manager) addARPNeighborWithHandle(
	handle *netlink.Handle,
	link netlink.Link,
	ipAddr, macAddr string,
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
			m.logger.V(3).Info("ARP neighbor entry already exists", "ip", ipAddr, "mac", macAddr)
			return nil
		}
		return fmt.Errorf("failed to add neighbor entry: %v", err)
	}

	m.logger.V(3).Info("Added static ARP neighbor entry", "ip", ipAddr, "mac", macAddr)
	return nil
}

// configureInterfaceWithHandle configures an interface using a specific netlink handle.
func (m *Manager) configureInterfaceWithHandle(
	handle *netlink.Handle,
	oldName, newName, ipAddr, macAddr, mtu, gateway string,
) error {
	// Find the interface in the target namespace
	link, err := handle.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("failed to find link %s in target namespace: %v", oldName, err)
	}

	// Rename interface if needed
	if newName != "" && oldName != newName {
		// Check if target interface name already exists
		if _, err := handle.LinkByName(newName); err == nil {
			return fmt.Errorf("interface %s already exists, cannot rename %s",
				newName, oldName)
		}

		if err := handle.LinkSetName(link, newName); err != nil {
			return fmt.Errorf("failed to rename interface %s to %s: %v", oldName, newName, err)
		}

		// Re-get the link with new name, with retry for timing issues
		var retryErr error
		for i := range 3 {
			if link, retryErr = handle.LinkByName(newName); retryErr == nil {
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
		return fmt.Errorf("failed to set interface up: %v", err)
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
				m.logger.V(2).Info("Default route already exists, skipping", "gateway", gateway)
			} else if strings.Contains(errStr, "network is unreachable") {
				// This often happens when the gateway is not in the same subnet as the interface IP
				m.logger.V(1).Info("Gateway unreachable - this may be expected for certain network configurations",
					"gateway", gateway, "interface", newName, "ip", ipAddr, "error", err)
				// Don't fail the operation for now, as this might be intentional
			} else {
				return fmt.Errorf("failed to add gateway route: %v", err)
			}
		} else {
			m.logger.V(2).Info("Added default gateway route", "gateway", gateway, "interface", newName)
		}
	}

	// Add ARP neighbor entry for the gateway if provided
	if ipAddr != "" {
		// Generate a deterministic MAC address for the gateway
		ipAddrMAC, err := generateDeterministicMAC(ipAddr)
		if err != nil {
			m.logger.V(1).Info("Failed to generate gateway MAC", "gateway", gateway, "error", err)
		} else {
			if err := m.addARPNeighborWithHandle(handle, link, ipAddr, ipAddrMAC.String()); err != nil {
				m.logger.V(1).Info("Failed to add interface ARP entry", "error", err)
				// Don't fail the operation for ARP neighbor failures
			}
		}
	}

	m.logger.V(3).Info("Configured interface with handle",
		"interface", newName,
		"ip", ipAddr,
		"mac", macAddr,
		"mtu", mtu,
		"gateway", gateway)

	return nil
}
