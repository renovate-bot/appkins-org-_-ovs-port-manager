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
	"github.com/appkins-org/ovs-port-manager/internal/models"
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
		"AutoAttach":                &models.AutoAttach{},
		"Bridge":                    &models.Bridge{},
		"Controller":                &models.Controller{},
		"Flow_Sample_Collector_Set": &models.FlowSampleCollectorSet{},
		"Flow_Table":                &models.FlowTable{},
		"IPFIX":                     &models.IPFIX{},
		"Interface":                 &models.Interface{},
		"Manager":                   &models.Manager{},
		"Mirror":                    &models.Mirror{},
		"NetFlow":                   &models.NetFlow{},
		"Open_vSwitch":              &models.OpenvSwitch{},
		"Port":                      &models.Port{},
		"QoS":                       &models.QoS{},
		"Queue":                     &models.Queue{},
		"SSL":                       &models.SSL{},
		"sFlow":                     &models.SFlow{},
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
	var bridges []models.Bridge
	err := m.ovsClient.WhereCache(func(b *models.Bridge) bool {
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
	bridge := &models.Bridge{
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
	// Get container PID to ensure container is running
	container, err := m.dockerClient.ContainerInspect(ctx, config.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %v", err)
	}

	if container.State.Pid == 0 {
		return fmt.Errorf("container is not running")
	}

	// Generate port name (this will be the base name for the veth pair)
	portName := m.generatePortName(config.ContainerID)

	// Check if port already exists for this container/interface combination
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

	// Add port to bridge (this creates the veth pair, adds to OVS, sets external IDs, and brings up host side)
	// This mirrors the complete ovs-docker add-port workflow
	if err := m.addPortToBridge(ctx, config.Bridge, portName, config.ContainerID, config.Interface); err != nil {
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Configure the container side (move to netns, rename, configure IP/MAC/MTU/gateway)
	containerSideName := portName + "_c" // Container side name
	if err := m.configureContainerInterface(config.ContainerID, containerSideName, config); err != nil {
		// Cleanup on failure: remove from OVS and delete veth pair
		hostSideName := portName + "_l"
		m.removePortFromOVSBridge(ctx, hostSideName)
		m.deleteLinkByName(hostSideName) // This will cleanup the entire veth pair
		return fmt.Errorf("failed to configure container interface: %v", err)
	}

	m.logger.WithFields(logrus.Fields{
		"container_id": config.ContainerID[:12],
		"bridge":       config.Bridge,
		"interface":    config.Interface,
		"ip_address":   config.IPAddress,
	}).Info("Successfully added OVS port using ovs-docker method")

	return nil
}

// removeOVSPort removes OVS ports associated with a container
// This mirrors the ovs-docker del-port and del-ports behavior
func (m *Manager) removeOVSPort(ctx context.Context, containerID string) error {
	// Find all ports for this container using external_ids
	// This mirrors: ovs-vsctl --data=bare --no-heading --columns=name find interface external_ids:container_id="$CONTAINER"
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
		}).Info("Removing OVS port (ovs-docker method)")

		// Remove port from OVS (mirroring: ovs-vsctl --if-exists del-port "$PORT")
		if err := m.removePortFromOVSBridge(ctx, portName); err != nil {
			m.logger.WithError(err).WithField("port_name", portName).Error("Failed to remove port from OVS")
		}

		// Delete the veth pair (mirroring: ip link delete "$PORT")
		// This will delete both sides of the veth pair
		if err := m.deleteLinkByName(portName); err != nil {
			m.logger.WithError(err).WithField("port_name", portName).Error("Failed to delete veth pair")
		}
	}

	m.logger.WithField("container_id", containerID[:12]).Info("Completed OVS port cleanup")
	return nil
}

// portExists checks if a port already exists for a container and interface
// This mirrors the get_port_for_container_interface check from ovs-docker
func (m *Manager) portExists(ctx context.Context, bridge, containerID, interfaceName string) (bool, error) {
	// Check using external_ids like ovs-docker does
	existingPort, err := m.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return false, fmt.Errorf("failed to check for existing port: %v", err)
	}

	return existingPort != "", nil
}

// generatePortName generates a unique port name for a container
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

// addPortToBridge adds a port to an OVS bridge, mirroring ovs-docker add-port exactly
func (m *Manager) addPortToBridge(ctx context.Context, bridge, portName, containerID, interfaceName string) error {
	// This function mirrors the ovs-docker add-port command exactly:
	// 1. Check if port already exists for this container/interface (get_port_for_container_interface)
	// 2. Create/ensure bridge exists (ovs-vsctl br-exists || ovs-vsctl add-br)
	// 3. Create veth pair: ${PORTNAME}_l and ${PORTNAME}_c
	// 4. Add host side to OVS bridge (ovs-vsctl --may-exist add-port)
	// 5. Set external_ids on interface
	// 6. Set host side link up

	hostSide := portName + "_l"      // Host side of veth pair
	containerSide := portName + "_c" // Container side of veth pair

	// Step 1: Check if port already exists (mirroring get_port_for_container_interface)
	existingPort, err := m.getPortForContainerInterface(ctx, containerID, interfaceName)
	if err != nil {
		return fmt.Errorf("failed to check for existing port: %v", err)
	}
	if existingPort != "" {
		return fmt.Errorf("port already attached for CONTAINER=%s and INTERFACE=%s (existing port: %s)",
			containerID[:12], interfaceName, existingPort)
	}

	// Step 2: Ensure bridge exists (mirroring: ovs-vsctl br-exists "$BRIDGE" || ovs-vsctl add-br "$BRIDGE")
	if err := m.ensureBridgeExists(ctx, bridge); err != nil {
		return fmt.Errorf("failed to create bridge %s: %v", bridge, err)
	}

	// Step 3: Create veth pair (mirroring: ip link add "${PORTNAME}_l" type veth peer name "${PORTNAME}_c")
	if err := m.createVethPairWithNames(hostSide, containerSide); err != nil {
		return fmt.Errorf("failed to create veth pair %s<->%s: %v", hostSide, containerSide, err)
	}

	// Step 4: Add host side to OVS bridge (mirroring: ovs-vsctl --may-exist add-port "$BRIDGE" "${PORTNAME}_l")
	if err := m.addPortToOVSBridge(ctx, bridge, hostSide); err != nil {
		// Cleanup veth pair on failure (mirroring: ip link delete "${PORTNAME}_l")
		m.deleteLinkByName(hostSide)
		return fmt.Errorf("failed to add %s port to bridge %s: %v", hostSide, bridge, err)
	}

	// Step 5: Set external_ids (mirroring: ovs-vsctl set interface "${PORTNAME}_l" external_ids:...)
	if err := m.setInterfaceExternalIDs(ctx, hostSide, containerID, interfaceName); err != nil {
		// Cleanup on failure
		m.removePortFromOVSBridge(ctx, hostSide)
		m.deleteLinkByName(hostSide)
		return fmt.Errorf("failed to set external IDs on interface %s: %v", hostSide, err)
	}

	// Step 6: Set host side link up (mirroring: ip link set "${PORTNAME}_l" up)
	if err := m.setLinkUp(hostSide); err != nil {
		// Cleanup on failure
		m.removePortFromOVSBridge(ctx, hostSide)
		m.deleteLinkByName(hostSide)
		return fmt.Errorf("failed to set link %s up: %v", hostSide, err)
	}

	m.logger.WithFields(logrus.Fields{
		"bridge":         bridge,
		"host_side":      hostSide,
		"container_side": containerSide,
		"container_id":   containerID[:12],
	}).Info("Added port to OVS bridge (ovs-docker method)")

	return nil
}

// createVethPairWithNames creates a veth pair with specific names
func (m *Manager) createVethPairWithNames(hostName, containerName string) error {
	// Create veth pair
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostName,
		},
		PeerName: containerName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	m.logger.WithFields(logrus.Fields{
		"host_side":      hostName,
		"container_side": containerName,
	}).Debug("Created veth pair")

	return nil
}

// addPortToOVSBridgeCommand adds a port to OVS bridge using command execution
// This mirrors: ovs-vsctl --may-exist add-port "$BRIDGE" "$PORT"
func (m *Manager) addPortToOVSBridgeCommand(bridge, portName string) error {
	// Use the OVS client to add port to bridge
	// Find the bridge first
	var bridges []models.Bridge
	err := m.ovsClient.WhereCache(func(b *models.Bridge) bool {
		return b.Name == bridge
	}).List(context.Background(), &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s: %v", bridge, err)
	}

	if len(bridges) == 0 {
		return fmt.Errorf("bridge %s not found", bridge)
	}

	// Create Port record first
	port := &models.Port{
		Name:        portName,
		Interfaces:  []string{}, // Will be populated when interface is created
		ExternalIDs: map[string]string{},
	}

	// Create Interface record
	iface := &models.Interface{
		Name:        portName,
		Type:        "",
		ExternalIDs: map[string]string{},
	}

	// Execute operations
	ops := []ovsdb.Operation{}

	// Create interface
	ifaceOps, err := m.ovsClient.Create(iface)
	if err != nil {
		return fmt.Errorf("failed to create interface operation: %v", err)
	}
	ops = append(ops, ifaceOps...)

	// Create port
	portOps, err := m.ovsClient.Create(port)
	if err != nil {
		return fmt.Errorf("failed to create port operation: %v", err)
	}
	ops = append(ops, portOps...)

	// Execute transaction
	_, err = m.ovsClient.Transact(context.Background(), ops...)
	if err != nil {
		return fmt.Errorf("failed to add port to OVS: %v", err)
	}

	return nil
}

// setInterfaceExternalIDs sets external IDs on an OVS interface
// This mirrors: ovs-vsctl set interface "$INTERFACE" external_ids:container_id="$CONTAINER" external_ids:container_iface="$IFACE"
func (m *Manager) setInterfaceExternalIDs(ctx context.Context, interfaceName, containerID, containerInterface string) error {
	// Find the interface
	var interfaces []models.Interface
	err := m.ovsClient.WhereCache(func(i *models.Interface) bool {
		return i.Name == interfaceName
	}).List(ctx, &interfaces)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %v", interfaceName, err)
	}

	if len(interfaces) == 0 {
		return fmt.Errorf("interface %s not found", interfaceName)
	}

	// Update external IDs
	iface := &interfaces[0]
	if iface.ExternalIDs == nil {
		iface.ExternalIDs = make(map[string]string)
	}
	iface.ExternalIDs["container_id"] = containerID
	iface.ExternalIDs["container_iface"] = containerInterface

	// Update the interface
	ops, err := m.ovsClient.Where(iface).Update(iface)
	if err != nil {
		return fmt.Errorf("failed to create update operation: %v", err)
	}

	_, err = m.ovsClient.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to update interface external IDs: %v", err)
	}

	return nil
}

// removePortFromOVSBridgeCommand removes a port from OVS bridge
// This mirrors: ovs-vsctl --if-exists del-port "$PORT"
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

// configureContainerInterface configures the container-side interface
// This mirrors the container configuration part of ovs-docker add-port:
// 1. Move "${PORTNAME}_c" inside the container (ip link set "${PORTNAME}_c" netns "$PID")
// 2. Rename it to the target interface name (ip netns exec "$PID" ip link set dev "${PORTNAME}_c" name "$INTERFACE")
// 3. Set interface up (ip netns exec "$PID" ip link set "$INTERFACE" up)
// 4. Set MTU if provided (ip netns exec "$PID" ip link set dev "$INTERFACE" mtu "$MTU")
// 5. Add IP address if provided (ip netns exec "$PID" ip addr add "$ADDRESS" dev "$INTERFACE")
// 6. Set MAC address if provided (ip netns exec "$PID" ip link set dev "$INTERFACE" address "$MACADDRESS")
// 7. Add gateway route if provided (ip netns exec "$PID" ip route add default via "$GATEWAY")
func (m *Manager) configureContainerInterface(containerID, containerSideName string, config *ContainerOVSConfig) error {
	// Get container PID (mirroring: docker inspect -f '{{.State.Pid}}' "$CONTAINER")
	container, err := m.dockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return fmt.Errorf("failed to get the PID of the container: %v", err)
	}

	if container.State.Pid == 0 {
		return fmt.Errorf("container is not running")
	}

	pid := container.State.Pid

	// Step 1: Move container side to container namespace
	// (mirroring: ip link set "${PORTNAME}_c" netns "$PID")
	if err := m.moveLinkToNetns(containerSideName, pid); err != nil {
		return fmt.Errorf("failed to move interface to container: %v", err)
	}

	// Steps 2-7: Configure interface inside container namespace
	// This mirrors all the ip netns exec commands from ovs-docker
	if err := m.configureInterfaceInNetns(pid, containerSideName, config.Interface,
		config.IPAddress, config.MACAddress, config.MTU, config.Gateway); err != nil {
		return fmt.Errorf("failed to configure interface in container: %v", err)
	}

	m.logger.WithFields(logrus.Fields{
		"container_id": containerID[:12],
		"interface":    config.Interface,
		"ip_address":   config.IPAddress,
		"mac_address":  config.MACAddress,
		"mtu":          config.MTU,
		"gateway":      config.Gateway,
	}).Info("Configured container interface (ovs-docker method)")

	return nil
}

// findPortsForContainer finds all OVS ports associated with a container
// This mirrors: ovs-vsctl --data=bare --no-heading --columns=name find interface external_ids:container_id="$CONTAINER"
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

	m.logger.WithFields(logrus.Fields{
		"container_id": containerID[:12],
		"port_count":   len(portNames),
		"ports":        portNames,
	}).Debug("Found ports for container")

	return portNames, nil
}

// cleanupOVSPort removes a port from OVS bridge and database
func (m *Manager) cleanupOVSPort(ctx context.Context, bridge, portName string) error {
	// Find all ports with this name
	var ports []models.Port
	err := m.ovsClient.WhereCache(func(p *models.Port) bool {
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
	var interfaces []models.Interface
	for _, port := range ports {
		for _, ifaceUUID := range port.Interfaces {
			var ifaces []models.Interface
			err := m.ovsClient.WhereCache(func(i *models.Interface) bool {
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

// getPortForContainerInterface finds a port for a container interface
// This mirrors the get_port_for_container_interface function from ovs-docker
func (m *Manager) getPortForContainerInterface(ctx context.Context, containerID, interfaceName string) (string, error) {
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
// This mirrors: ovs-vsctl br-exists "$BRIDGE" || ovs-vsctl add-br "$BRIDGE"
func (m *Manager) ensureBridgeExists(ctx context.Context, bridgeName string) error {
	// Check if bridge exists
	var bridges []models.Bridge
	err := m.ovsClient.WhereCache(func(b *models.Bridge) bool {
		return b.Name == bridgeName
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to check if bridge exists: %v", err)
	}

	if len(bridges) > 0 {
		// Bridge already exists
		return nil
	}

	// Create the bridge
	bridge := &models.Bridge{
		Name:        bridgeName,
		Ports:       []string{},
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	ops, err := m.ovsClient.Create(bridge)
	if err != nil {
		return fmt.Errorf("failed to create bridge operation: %v", err)
	}

	_, err = m.ovsClient.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to create bridge: %v", err)
	}

	m.logger.WithField("bridge", bridgeName).Info("Created OVS bridge")
	return nil
}

// addPortToOVSBridge adds a port to an OVS bridge
// This mirrors: ovs-vsctl --may-exist add-port "$BRIDGE" "$PORT"
func (m *Manager) addPortToOVSBridge(ctx context.Context, bridgeName, portName string) error {
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

	// Create Interface record
	iface := &models.Interface{
		Name:        portName,
		Type:        "",
		ExternalIDs: map[string]string{},
	}

	// Create Port record
	port := &models.Port{
		Name:        portName,
		Interfaces:  []string{}, // Will be linked after interface creation
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
	bridge.Ports = append(bridge.Ports, port.UUID)
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

// removePortFromOVSBridge removes a port from OVS bridge
// This mirrors: ovs-vsctl --if-exists del-port "$PORT"
func (m *Manager) removePortFromOVSBridge(ctx context.Context, portName string) error {
	return m.removePortFromOVSBridgeCommand(portName)
}
