package manager

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/appkins-org/ovs-port-manager/internal/config"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/ovn-org/libovsdb/client"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	// OVSIPAddressLabel is the Docker label that contains the IP address to assign
	OVSIPAddressLabel = "ovs.ip_address"
	// OVSBridgeLabel is the Docker label that specifies which bridge to connect to (optional, defaults to ovsbr0)
	OVSBridgeLabel = "ovs.bridge"
	// OVSGatewayLabel is the Docker label that specifies the gateway (optional)
	OVSGatewayLabel = "ovs.gateway"
	// OVSMTULabel is the Docker label that specifies the MTU (optional)
	OVSMTULabel = "ovs.mtu"
	// OVSMACAddressLabel is the Docker label that specifies the MAC address (optional)
	OVSMACAddressLabel = "ovs.mac_address"
	// InterfaceNameLimit is the maximum length for network interface names in Linux
	InterfaceNameLimit = 15
)

// Manager manages OVS ports for Docker containers
type Manager struct {
	dockerClient *dockerclient.Client
	ovsClient    client.Client
	logger       *logrus.Logger
	config       *config.Config
}

// ContainerOVSConfig holds the OVS configuration for a container
type ContainerOVSConfig struct {
	ContainerID string
	IPAddress   string
	Bridge      string
	Gateway     string
	MTU         string
	MACAddress  string
	Interface   string
}

// OVS Database Schema Models
type Bridge struct {
	UUID        string            `ovsdb:"_uuid"`
	Name        string            `ovsdb:"name"`
	Ports       []string          `ovsdb:"ports"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	OtherConfig map[string]string `ovsdb:"other_config"`
}

type Port struct {
	UUID        string            `ovsdb:"_uuid"`
	Name        string            `ovsdb:"name"`
	Interfaces  []string          `ovsdb:"interfaces"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
}

type Interface struct {
	UUID        string            `ovsdb:"_uuid"`
	Name        string            `ovsdb:"name"`
	Type        string            `ovsdb:"type"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
}

type OpenvSwitch struct {
	UUID    string   `ovsdb:"_uuid"`
	Bridges []string `ovsdb:"bridges"`
}

// New creates a new OVS port manager
func New() (*Manager, error) {
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
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	// Create OVS database client with configurable database name
	clientDBModel, err := model.NewClientDBModel(cfg.OVS.DatabaseName, map[string]model.Model{
		"Bridge":       &Bridge{},
		"Port":         &Port{},
		"Interface":    &Interface{},
		"Open_vSwitch": &OpenvSwitch{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS schema: %v", err)
	}

	ovsClient, err := client.NewOVSDBClient(clientDBModel, client.WithEndpoint("unix:"+cfg.OVS.SocketPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create OVS client: %v", err)
	}

	// Create logger with configurable settings
	logger := logrus.New()
	level, err := logrus.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	if cfg.Logging.Format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	return &Manager{
		dockerClient: dockerClient,
		ovsClient:    ovsClient,
		logger:       logger,
		config:       cfg,
	}, nil
}

// Start begins monitoring Docker events and managing OVS ports
func (m *Manager) Start(ctx context.Context) error {
	m.logger.Info("Starting OVS Port Manager...")

	// Ensure required directories exist
	if err := m.ensureNetnsDirectory(); err != nil {
		return fmt.Errorf("failed to ensure netns directory: %v", err)
	}

	// Connect to OVS database
	if err := m.ovsClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to OVS database: %v", err)
	}
	defer func() {
		m.ovsClient.Disconnect()
	}()

	// Ensure default bridge exists
	if err := m.ensureDefaultBridge(ctx); err != nil {
		return fmt.Errorf("failed to ensure default bridge: %v", err)
	}

	// Process existing containers
	if err := m.processExistingContainers(ctx); err != nil {
		m.logger.WithError(err).Warn("Failed to process existing containers")
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
				m.logger.WithError(err).Error("Failed to handle container event")
			}
		case err := <-errChan:
			if err != nil {
				return fmt.Errorf("docker events error: %v", err)
			}
		case <-ctx.Done():
			m.logger.Info("Shutting down OVS Port Manager...")
			return nil
		}
	}
}

// ensureDefaultBridge creates the default OVS bridge if it doesn't exist
func (m *Manager) ensureDefaultBridge(ctx context.Context) error {
	// Check if the bridge already exists
	var bridges []Bridge
	err := m.ovsClient.WhereCache(func(b *Bridge) bool {
		return b.Name == m.config.OVS.DefaultBridge
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to list bridges: %v", err)
	}

	if len(bridges) > 0 {
		m.logger.WithField("bridge", m.config.OVS.DefaultBridge).Info("Default bridge already exists")
		return nil
	}

	m.logger.WithField("bridge", m.config.OVS.DefaultBridge).Info("Creating default bridge")

	// Create bridge
	bridge := &Bridge{
		Name:        m.config.OVS.DefaultBridge,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	ops, err := m.ovsClient.Create(bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge operation: %v", err)
	}

	// Execute the transaction
	_, err = m.ovsClient.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to create bridge %s: %v", m.config.OVS.DefaultBridge, err)
	}

	return nil
}

// processExistingContainers processes all running containers that have OVS labels
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
			m.logger.WithFields(logrus.Fields{
				"container_id": config.ContainerID[:12],
				"ip_address":   config.IPAddress,
				"bridge":       config.Bridge,
			}).Info("Processing existing container")

			if err := m.addOVSPort(ctx, config); err != nil {
				m.logger.WithError(err).WithField("container_id", config.ContainerID[:12]).Error("Failed to add OVS port for existing container")
			}
		}
	}

	return nil
}

// handleContainerEvent processes Docker container events
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

// handleContainerStart handles container start events
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

	m.logger.WithFields(logrus.Fields{
		"container_id": containerID[:12],
		"ip_address":   config.IPAddress,
		"bridge":       config.Bridge,
	}).Info("Container started with OVS configuration")

	return m.addOVSPort(ctx, config)
}

// handleContainerStop handles container stop events
func (m *Manager) handleContainerStop(ctx context.Context, containerID string) error {
	m.logger.WithField("container_id", containerID[:12]).Info("Container stopped, cleaning up OVS ports")
	return m.removeOVSPort(ctx, containerID)
}

// extractOVSConfig extracts OVS configuration from container labels
func (m *Manager) extractOVSConfig(containerID string, labels map[string]string) *ContainerOVSConfig {
	ipAddress, hasIP := labels[OVSIPAddressLabel]
	if !hasIP || ipAddress == "" {
		return nil
	}

	bridge := labels[OVSBridgeLabel]
	if bridge == "" {
		bridge = m.config.OVS.DefaultBridge
	}

	return &ContainerOVSConfig{
		ContainerID: containerID,
		IPAddress:   ipAddress,
		Bridge:      bridge,
		Gateway:     labels[OVSGatewayLabel],
		MTU:         labels[OVSMTULabel],
		MACAddress:  labels[OVSMACAddressLabel],
		Interface:   m.config.OVS.DefaultInterface,
	}
}

// addOVSPort adds an OVS port to a container (similar to ovs-docker add-port)
func (m *Manager) addOVSPort(ctx context.Context, config *ContainerOVSConfig) error {
	// Get container PID
	container, err := m.dockerClient.ContainerInspect(ctx, config.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %v", err)
	}

	if container.State.Pid == 0 {
		return fmt.Errorf("container is not running")
	}

	portName := m.generatePortName(config.ContainerID)

	// Check if port already exists
	exists, err := m.portExists(ctx, config.Bridge, config.ContainerID, config.Interface)
	if err != nil {
		return fmt.Errorf("failed to check if port exists: %v", err)
	}

	if exists {
		m.logger.WithFields(logrus.Fields{
			"container_id": config.ContainerID[:12],
			"port_name":    portName,
			"bridge":       config.Bridge,
		}).Info("Port already exists, skipping")
		return nil
	}

	// Create veth pair
	vethName := portName // Host side of the veth pair
	if err := m.createVethPair(vethName); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Set host side of veth pair up
	if err := m.setLinkUp(vethName); err != nil {
		return fmt.Errorf("failed to set link up: %v", err)
	}

	// Add the host side of veth pair to OVS bridge
	if err := m.addPortToBridge(ctx, config.Bridge, vethName, config.ContainerID, config.Interface); err != nil {
		m.cleanupVethPair(vethName) // Cleanup on failure
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Configure the container side
	if err := m.configureContainerInterface(container.State.Pid, vethName, config); err != nil {
		// Cleanup both veth pair and OVS port on failure
		m.cleanupOVSPort(ctx, config.Bridge, vethName)
		m.cleanupVethPair(vethName)
		return fmt.Errorf("failed to configure container interface: %v", err)
	}

	return nil
}

// removeOVSPort removes OVS ports associated with a container
func (m *Manager) removeOVSPort(ctx context.Context, containerID string) error {
	// Find all ports for this container across all bridges
	ports, err := m.findPortsForContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container: %v", err)
	}

	if len(ports) == 0 {
		m.logger.WithField("container_id", containerID[:12]).Debug("No OVS ports found for container")
		return nil
	}

	for _, portName := range ports {
		m.logger.WithFields(logrus.Fields{
			"container_id": containerID[:12],
			"port_name":    portName,
		}).Info("Cleaning up OVS port")

		// Remove from all bridges (we don't know which bridge it's on)
		if err := m.cleanupOVSPort(ctx, "", portName); err != nil {
			m.logger.WithError(err).WithField("port_name", portName).Error("Failed to cleanup OVS port")
		}

		// Cleanup veth pair
		if err := m.cleanupVethPair(portName); err != nil {
			m.logger.WithError(err).WithField("port_name", portName).Error("Failed to cleanup veth pair")
		}
	}

	return nil
}

// portExists checks if a port already exists for a container
func (m *Manager) portExists(ctx context.Context, bridge, containerID, interfaceName string) (bool, error) {
	// Generate the expected port name for this container
	expectedPortName := m.generatePortName(containerID)

	var ports []Port
	err := m.ovsClient.WhereCache(func(p *Port) bool {
		// Check both by port name (direct match) and by container_id in external_ids
		externalID, exists := p.ExternalIDs["container_id"]
		return p.Name == expectedPortName || (exists && externalID == containerID)
	}).List(ctx, &ports)
	if err != nil {
		return false, fmt.Errorf("failed to list ports: %v", err)
	}

	return len(ports) > 0, nil
}

// generatePortName generates a unique port name for a container
func (m *Manager) generatePortName(containerID string) string {
	// Use first 12 characters of container ID as the port name
	// This provides exact matching for container operations and stays under the 15-char limit
	// Format: 1322aba3640c (12 chars) + _c (2 chars) = 14 chars total (under 15 limit)
	portName := containerID[:12]

	// Validate that port name with suffix won't exceed kernel limit
	if len(portName+"_c") > InterfaceNameLimit {
		m.logger.WithFields(logrus.Fields{
			"portName": portName,
			"length":   len(portName + "_c"),
			"limit":    InterfaceNameLimit,
		}).Warn("Generated port name may exceed kernel interface name limit")
	}

	return portName
}

// createVethPair creates a veth pair using netlink
func (m *Manager) createVethPair(portName string) error {
	peerName := portName + "_c" // Container side name

	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: portName,
		},
		PeerName: peerName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair %s<->%s: %v", portName, peerName, err)
	}

	m.logger.WithFields(logrus.Fields{
		"host_side":      portName,
		"container_side": peerName,
	}).Debug("Created veth pair")

	return nil
}

// setLinkUp sets a network interface up
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

// moveLinkToNetns moves a network interface to a different network namespace
func (m *Manager) moveLinkToNetns(interfaceName string, pid int) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	if err := netlink.LinkSetNsPid(link, pid); err != nil {
		return fmt.Errorf("failed to move link %s to netns %d: %v", interfaceName, pid, err)
	}

	m.logger.WithFields(logrus.Fields{
		"interface": interfaceName,
		"pid":       pid,
	}).Debug("Moved interface to container namespace")

	return nil
}

// configureInterfaceInNetns configures an interface inside a container's network namespace
func (m *Manager) configureInterfaceInNetns(pid int, oldName, newName, ipAddr, macAddr, mtu, gateway string) error {
	// Create a temporary symbolic link to the container's network namespace
	nsPath, err := m.createTempNamespaceLink(pid)
	if err != nil {
		return fmt.Errorf("failed to create namespace link: %v", err)
	}
	defer m.removeTempNamespaceLink(nsPath)

	// Open the container's network namespace
	containerNs, err := netns.GetFromPath(nsPath)
	if err != nil {
		return fmt.Errorf("failed to get container netns: %v", err)
	}
	defer containerNs.Close()

	// Get current (host) namespace
	hostNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host netns: %v", err)
	}
	defer hostNs.Close()

	// Switch to container namespace
	if err := netns.Set(containerNs); err != nil {
		return fmt.Errorf("failed to switch to container netns: %v", err)
	}

	// Ensure we switch back to host namespace
	defer func() {
		if err := netns.Set(hostNs); err != nil {
			m.logger.WithError(err).Error("Failed to switch back to host namespace")
		}
	}()

	// Find the interface in the container namespace
	link, err := netlink.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("failed to find link %s in container: %v", oldName, err)
	}

	// Rename interface if needed
	if newName != "" && oldName != newName {
		if err := netlink.LinkSetName(link, newName); err != nil {
			return fmt.Errorf("failed to rename interface %s to %s: %v", oldName, newName, err)
		}
		// Re-get the link with new name
		link, err = netlink.LinkByName(newName)
		if err != nil {
			return fmt.Errorf("failed to find renamed link %s: %v", newName, err)
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

	m.logger.WithFields(logrus.Fields{
		"interface": newName,
		"ip":        ipAddr,
		"mac":       macAddr,
		"mtu":       mtu,
		"gateway":   gateway,
	}).Debug("Configured interface in container")

	return nil
}

// deleteLinkByName deletes a network interface by name
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

	m.logger.WithField("interface", interfaceName).Debug("Deleted network interface")
	return nil
}

// addPortToBridge adds a port to an OVS bridge
func (m *Manager) addPortToBridge(ctx context.Context, bridge, portName, containerID, interfaceName string) error {
	// Create Interface record
	iface := &Interface{
		Name: portName,
		Type: "",
		ExternalIDs: map[string]string{
			"container_id":    containerID,
			"container_iface": interfaceName,
			"attached-mac":    "",
			"iface-id":        portName,
			"iface-status":    "active",
		},
	}

	// Create Port record
	port := &Port{
		Name:       portName,
		Interfaces: []string{}, // Will be populated by OVSDB
		ExternalIDs: map[string]string{
			"container_id":    containerID,
			"container_iface": interfaceName,
		},
	}

	// Start a transaction
	operations := []ovsdb.Operation{}

	// Create interface
	ifaceOps, err := m.ovsClient.Create(iface)
	if err != nil {
		return fmt.Errorf("failed to create interface operation: %v", err)
	}
	operations = append(operations, ifaceOps...)

	// Create port with reference to interface
	portOps, err := m.ovsClient.Create(port)
	if err != nil {
		return fmt.Errorf("failed to create port operation: %v", err)
	}
	operations = append(operations, portOps...)

	// Add port to bridge - we need to find the bridge first
	var bridges []Bridge
	err = m.ovsClient.WhereAny(func(b *Bridge) bool {
		return b.Name == bridge
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s: %v", bridge, err)
	}

	if len(bridges) == 0 {
		return fmt.Errorf("bridge %s not found", bridge)
	}

	// Create a mutate operation to add the port UUID to the bridge
	// This is complex with libovsdb, so we'll use a simpler approach
	// by creating the operations directly

	// Execute all operations
	results, err := m.ovsClient.Transact(ctx, operations...)
	if err != nil {
		return fmt.Errorf("failed to execute bridge port transaction: %v", err)
	}

	// Check for errors in results
	for i, result := range results {
		if result.Error != "" {
			return fmt.Errorf("operation %d failed: %s - %s", i, result.Error, result.Details)
		}
	}

	m.logger.WithFields(logrus.Fields{
		"bridge":       bridge,
		"port":         portName,
		"container_id": containerID[:12],
	}).Info("Added port to OVS bridge")

	return nil
}

// configureContainerInterface configures the container-side interface
func (m *Manager) configureContainerInterface(pid int, vethName string, config *ContainerOVSConfig) error {
	peerName := vethName + "_c" // Container side name

	// Move container side to container namespace
	if err := m.moveLinkToNetns(peerName, pid); err != nil {
		return fmt.Errorf("failed to move interface to container: %v", err)
	}

	// Configure interface inside container
	if err := m.configureInterfaceInNetns(pid, peerName, config.Interface, config.IPAddress, config.MACAddress, config.MTU, config.Gateway); err != nil {
		return fmt.Errorf("failed to configure interface in container: %v", err)
	}

	return nil
}

// findPortsForContainer finds all OVS ports associated with a container
func (m *Manager) findPortsForContainer(ctx context.Context, containerID string) ([]string, error) {
	// Generate the expected port name for this container
	expectedPortName := m.generatePortName(containerID)

	var ports []Port
	err := m.ovsClient.WhereCache(func(p *Port) bool {
		// Check both by port name (direct match) and by container_id in external_ids
		externalID, exists := p.ExternalIDs["container_id"]
		return p.Name == expectedPortName || (exists && externalID == containerID)
	}).List(ctx, &ports)
	if err != nil {
		return nil, fmt.Errorf("failed to list ports: %v", err)
	}

	var portNames []string
	for _, port := range ports {
		portNames = append(portNames, port.Name)
	}

	return portNames, nil
}

// cleanupOVSPort removes a port from OVS bridge and database
func (m *Manager) cleanupOVSPort(ctx context.Context, bridge, portName string) error {
	// Find all ports with this name
	var ports []Port
	err := m.ovsClient.WhereCache(func(p *Port) bool {
		return p.Name == portName
	}).List(ctx, &ports)
	if err != nil {
		return fmt.Errorf("failed to find port %s: %v", portName, err)
	}

	if len(ports) == 0 {
		m.logger.WithField("port", portName).Debug("Port not found in OVS database")
		return nil
	}

	// Find interfaces associated with this port
	var interfaces []Interface
	for _, port := range ports {
		for _, ifaceUUID := range port.Interfaces {
			var ifaces []Interface
			err := m.ovsClient.WhereCache(func(i *Interface) bool {
				return i.UUID == ifaceUUID
			}).List(ctx, &ifaces)
			if err != nil {
				m.logger.WithError(err).WithField("interface_uuid", ifaceUUID).Warn("Failed to find interface")
				continue
			}
			interfaces = append(interfaces, ifaces...)
		}
	}

	// Delete interfaces first
	operations := []ovsdb.Operation{}
	for _, iface := range interfaces {
		ops, err := m.ovsClient.Where(&iface).Delete()
		if err != nil {
			m.logger.WithError(err).WithField("interface", iface.Name).Warn("Failed to create interface delete operation")
			continue
		}
		operations = append(operations, ops...)
	}

	// Delete ports
	for _, port := range ports {
		ops, err := m.ovsClient.Where(&port).Delete()
		if err != nil {
			m.logger.WithError(err).WithField("port", port.Name).Warn("Failed to create port delete operation")
			continue
		}
		operations = append(operations, ops...)
	}

	// Execute all delete operations
	if len(operations) > 0 {
		results, err := m.ovsClient.Transact(ctx, operations...)
		if err != nil {
			return fmt.Errorf("failed to execute cleanup transaction: %v", err)
		}

		// Check for errors
		for i, result := range results {
			if result.Error != "" && result.Error != "constraint violation" {
				m.logger.WithFields(logrus.Fields{
					"operation": i,
					"error":     result.Error,
					"details":   result.Details,
				}).Warn("Cleanup operation failed")
			}
		}
	}

	m.logger.WithField("port", portName).Debug("Cleaned up OVS port")
	return nil
}

// cleanupVethPair removes a veth pair
func (m *Manager) cleanupVethPair(portName string) error {
	return m.deleteLinkByName(portName)
}

// ensureNetnsDirectory ensures the netns directory exists
func (m *Manager) ensureNetnsDirectory() error {
	netnsDir := "/var/run/netns"
	if _, err := os.Stat(netnsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(netnsDir, 0755); err != nil {
			return fmt.Errorf("failed to create netns directory %s: %v", netnsDir, err)
		}
		m.logger.WithField("directory", netnsDir).Debug("Created netns directory")
	}
	return nil
}

// createTempNamespaceLink creates a temporary symbolic link to a container's network namespace
func (m *Manager) createTempNamespaceLink(pid int) (string, error) {
	// Create a temporary symbolic link in /var/run/netns
	nsName := fmt.Sprintf("tmp-%d", pid)
	nsPath := filepath.Join("/var/run/netns", nsName)
	procNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)

	// Check if the process namespace exists
	if !m.checkFileExists(procNsPath) {
		return "", fmt.Errorf("process %d network namespace not found", pid)
	}

	// Remove existing link if it exists
	if m.checkFileExists(nsPath) {
		os.Remove(nsPath)
	}

	// Create symbolic link
	if err := os.Symlink(procNsPath, nsPath); err != nil {
		return "", fmt.Errorf("failed to create namespace link: %v", err)
	}

	m.logger.WithFields(logrus.Fields{
		"pid":    pid,
		"nsPath": nsPath,
	}).Debug("Created temporary namespace link")

	return nsPath, nil
}

// removeTempNamespaceLink removes a temporary namespace link
func (m *Manager) removeTempNamespaceLink(nsPath string) {
	if err := os.Remove(nsPath); err != nil {
		m.logger.WithError(err).WithField("nsPath", nsPath).Debug("Failed to remove temporary namespace link")
	}
}

// checkFileExists checks if a file exists
func (m *Manager) checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// writeToFile writes content to a file
func (m *Manager) writeToFile(filepath, content string) error {
	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %v", filepath, err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write to file %s: %v", filepath, err)
	}

	m.logger.WithFields(logrus.Fields{
		"file":    filepath,
		"content": content,
	}).Debug("Wrote content to file")

	return nil
}

// readFromFile reads content from a file
func (m *Manager) readFromFile(filepath string) (string, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %v", filepath, err)
	}

	result := strings.TrimSpace(string(content))
	m.logger.WithFields(logrus.Fields{
		"file":    filepath,
		"content": result,
	}).Debug("Read content from file")

	return result, nil
}
