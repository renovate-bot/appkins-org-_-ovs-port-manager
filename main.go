package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
	// DefaultBridge is the default OVS bridge name
	DefaultBridge = "ovs_bond0"
	// DefaultInterface is the default interface name inside container
	DefaultInterface = "bond0"
)

// OVSPortManager manages OVS ports for Docker containers
type OVSPortManager struct {
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

// NewOVSPortManager creates a new OVS port manager
func NewOVSPortManager() (*OVSPortManager, error) {
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

	return &OVSPortManager{
		dockerClient: dockerClient,
		ovsClient:    ovsClient,
		logger:       logger,
		config:       cfg,
	}, nil
}

// Start begins monitoring Docker events and managing OVS ports
func (m *OVSPortManager) Start(ctx context.Context) error {
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
func (m *OVSPortManager) ensureDefaultBridge(ctx context.Context) error {
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
func (m *OVSPortManager) processExistingContainers(ctx context.Context) error {
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
func (m *OVSPortManager) handleContainerEvent(ctx context.Context, event events.Message) error {
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
func (m *OVSPortManager) handleContainerStart(ctx context.Context, containerID string) error {
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
func (m *OVSPortManager) handleContainerStop(ctx context.Context, containerID string) error {
	m.logger.WithField("container_id", containerID[:12]).Info("Container stopped, cleaning up OVS ports")
	return m.removeOVSPort(ctx, containerID)
}

// extractOVSConfig extracts OVS configuration from container labels
func (m *OVSPortManager) extractOVSConfig(containerID string, labels map[string]string) *ContainerOVSConfig {
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
func (m *OVSPortManager) addOVSPort(ctx context.Context, config *ContainerOVSConfig) error {
	// Get container PID
	container, err := m.dockerClient.ContainerInspect(ctx, config.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to inspect container: %v", err)
	}

	if container.State.Pid == 0 {
		return fmt.Errorf("container is not running")
	}

	// Check if port already exists
	if exists, err := m.portExists(ctx, config.Bridge, config.ContainerID, config.Interface); err != nil {
		return fmt.Errorf("failed to check if port exists: %v", err)
	} else if exists {
		m.logger.WithField("container_id", config.ContainerID[:12]).Info("OVS port already exists")
		return nil
	}

	// Create port using ovs-docker pattern
	portName := m.generatePortName(config.ContainerID)

	m.logger.WithFields(logrus.Fields{
		"container_id": config.ContainerID[:12],
		"port_name":    portName,
		"bridge":       config.Bridge,
	}).Info("Creating OVS port")

	// Execute ovs-docker equivalent operations
	if err := m.createVethPair(portName); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	// Add the bridge-side interface to OVS
	if err := m.addPortToBridge(ctx, config.Bridge, portName+"_l", config.ContainerID, config.Interface); err != nil {
		m.cleanupVethPair(portName)
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Move container-side interface to container namespace and configure it
	if err := m.configureContainerInterface(container.State.Pid, portName+"_c", config); err != nil {
		m.cleanupOVSPort(ctx, config.Bridge, portName+"_l")
		m.cleanupVethPair(portName)
		return fmt.Errorf("failed to configure container interface: %v", err)
	}

	m.logger.WithField("container_id", config.ContainerID[:12]).Info("Successfully added OVS port")
	return nil
}

// removeOVSPort removes OVS ports for a container
func (m *OVSPortManager) removeOVSPort(ctx context.Context, containerID string) error {
	// Find all ports for this container
	ports, err := m.findPortsForContainer(ctx, containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container: %v", err)
	}

	for _, port := range ports {
		m.logger.WithFields(logrus.Fields{
			"container_id": containerID[:12],
			"port":         port,
		}).Info("Removing OVS port")

		if err := m.cleanupOVSPort(ctx, "", port); err != nil {
			m.logger.WithError(err).WithField("port", port).Error("Failed to cleanup OVS port")
		}

		if err := m.cleanupVethPair(strings.TrimSuffix(port, "_l")); err != nil {
			m.logger.WithError(err).WithField("port", port).Error("Failed to cleanup veth pair")
		}
	}

	return nil
}

// portExists checks if a port already exists for the container and interface
func (m *OVSPortManager) portExists(ctx context.Context, bridge, containerID, interfaceName string) (bool, error) {
	// Check if there's already an interface for this container and interface name
	var interfaces []Interface
	err := m.ovsClient.WhereCache(func(i *Interface) bool {
		if externalIDs := i.ExternalIDs; externalIDs != nil {
			return externalIDs["container_id"] == containerID && externalIDs["container_iface"] == interfaceName
		}
		return false
	}).List(ctx, &interfaces)

	if err != nil {
		return false, fmt.Errorf("failed to query OVS interfaces: %v", err)
	}

	return len(interfaces) > 0, nil
}

// generatePortName generates a unique port name based on container ID
func (m *OVSPortManager) generatePortName(containerID string) string {
	// Use first 13 characters of container ID as port name prefix
	// This mirrors the ovs-docker behavior
	if len(containerID) > 13 {
		return containerID[:13]
	}
	return containerID
}

// createVethPair creates a veth pair for the container using netlink
func (m *OVSPortManager) createVethPair(portName string) error {
	// Create veth pair: portName_l <-> portName_c
	vethLink := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: portName + "_l",
		},
		PeerName: portName + "_c",
	}

	if err := netlink.LinkAdd(vethLink); err != nil {
		return fmt.Errorf("failed to create veth pair: %v", err)
	}

	m.logger.WithFields(logrus.Fields{
		"host_veth":      portName + "_l",
		"container_veth": portName + "_c",
	}).Debug("Created veth pair")

	return nil
}

// setLinkUp brings up a network interface using netlink
func (m *OVSPortManager) setLinkUp(interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %v", interfaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set link %s up: %v", interfaceName, err)
	}

	m.logger.WithField("interface", interfaceName).Debug("Set interface up")
	return nil
}

// moveLinkToNetns moves a network interface to a network namespace
func (m *OVSPortManager) moveLinkToNetns(interfaceName string, pid int) error {
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
	}).Debug("Moved interface to network namespace")
	return nil
}

// configureInterfaceInNetns configures an interface inside a network namespace
func (m *OVSPortManager) configureInterfaceInNetns(pid int, oldName, newName, ipAddr, macAddr, mtu, gateway string) error {
	// Get the network namespace
	nsHandle, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("failed to get netns for pid %d: %v", pid, err)
	}
	defer nsHandle.Close()

	// Create a netlink handle for the target namespace
	nlHandle, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle for netns: %v", err)
	}
	defer nlHandle.Delete()

	// Find the link in the namespace (it should be using the old name)
	link, err := nlHandle.LinkByName(oldName)
	if err != nil {
		return fmt.Errorf("failed to find link %s in netns: %v", oldName, err)
	}

	// Rename the interface if needed
	if oldName != newName {
		if err := nlHandle.LinkSetName(link, newName); err != nil {
			return fmt.Errorf("failed to rename interface from %s to %s: %v", oldName, newName, err)
		}
		// Re-get the link with the new name
		link, err = nlHandle.LinkByName(newName)
		if err != nil {
			return fmt.Errorf("failed to find renamed link %s: %v", newName, err)
		}
	}

	// Set MAC address if provided
	if macAddr != "" {
		mac, err := net.ParseMAC(macAddr)
		if err != nil {
			return fmt.Errorf("failed to parse MAC address %s: %v", macAddr, err)
		}
		if err := nlHandle.LinkSetHardwareAddr(link, mac); err != nil {
			return fmt.Errorf("failed to set MAC address: %v", err)
		}
	}

	// Set MTU if provided
	if mtu != "" {
		mtuInt, err := strconv.Atoi(mtu)
		if err != nil {
			return fmt.Errorf("failed to parse MTU %s: %v", mtu, err)
		}
		if err := nlHandle.LinkSetMTU(link, mtuInt); err != nil {
			return fmt.Errorf("failed to set MTU: %v", err)
		}
	}

	// Bring up the interface
	if err := nlHandle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	// Add IP address if provided
	if ipAddr != "" {
		addr, err := netlink.ParseAddr(ipAddr)
		if err != nil {
			return fmt.Errorf("failed to parse IP address %s: %v", ipAddr, err)
		}
		if err := nlHandle.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add IP address: %v", err)
		}
	}

	// Add default route if gateway is provided
	if gateway != "" {
		gw := net.ParseIP(gateway)
		if gw == nil {
			return fmt.Errorf("failed to parse gateway IP %s", gateway)
		}

		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        gw,
		}

		if err := nlHandle.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add default route: %v", err)
		}
	}

	m.logger.WithFields(logrus.Fields{
		"interface": newName,
		"ip":        ipAddr,
		"mac":       macAddr,
		"mtu":       mtu,
		"gateway":   gateway,
	}).Debug("Configured interface in network namespace")

	return nil
}

// deleteLinkByName deletes a network interface by name
func (m *OVSPortManager) deleteLinkByName(interfaceName string) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// Interface might not exist, which is fine for cleanup
		m.logger.WithField("interface", interfaceName).Debug("Interface not found, skipping deletion")
		return nil
	}

	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete link %s: %v", interfaceName, err)
	}

	m.logger.WithField("interface", interfaceName).Debug("Deleted interface")
	return nil
}

// addPortToBridge adds the bridge-side veth interface to the OVS bridge
func (m *OVSPortManager) addPortToBridge(ctx context.Context, bridge, portName, containerID, interfaceName string) error {
	// Create the interface
	iface := &Interface{
		Name: portName,
		Type: "",
		ExternalIDs: map[string]string{
			"container_id":    containerID,
			"container_iface": interfaceName,
		},
	}

	// Create the port
	port := &Port{
		Name: portName,
		ExternalIDs: map[string]string{
			"container_id":    containerID,
			"container_iface": interfaceName,
		},
	}

	// Start transaction operations
	var ops []ovsdb.Operation

	// Create interface
	ifaceOps, err := m.ovsClient.Create(iface)
	if err != nil {
		return fmt.Errorf("failed to create interface operation: %v", err)
	}
	ops = append(ops, ifaceOps...)

	// Create port and reference the interface
	port.Interfaces = []string{iface.UUID}
	portOps, err := m.ovsClient.Create(port)
	if err != nil {
		return fmt.Errorf("failed to create port operation: %v", err)
	}
	ops = append(ops, portOps...)

	// Get the bridge and add the port to it
	var bridges []Bridge
	err = m.ovsClient.WhereCache(func(b *Bridge) bool {
		return b.Name == bridge
	}).List(ctx, &bridges)
	if err != nil {
		return fmt.Errorf("failed to find bridge %s: %v", bridge, err)
	}

	if len(bridges) == 0 {
		return fmt.Errorf("bridge %s not found", bridge)
	}

	// Update bridge to include the new port
	bridgeUpdate := bridges[0]
	bridgeUpdate.Ports = append(bridgeUpdate.Ports, port.UUID)

	updateOps, err := m.ovsClient.Where(bridgeUpdate).Update(&bridgeUpdate, &bridgeUpdate)
	if err != nil {
		return fmt.Errorf("failed to create bridge update operation: %v", err)
	}
	ops = append(ops, updateOps...)

	// Execute the transaction
	_, err = m.ovsClient.Transact(ctx, ops...)
	if err != nil {
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Bring up the bridge-side interface using netlink
	return m.setLinkUp(portName)
}

// configureContainerInterface moves and configures the container-side interface
func (m *OVSPortManager) configureContainerInterface(pid int, vethName string, config *ContainerOVSConfig) error {
	// Move interface to container namespace
	if err := m.moveLinkToNetns(vethName, pid); err != nil {
		return fmt.Errorf("failed to move interface to netns: %v", err)
	}

	// Configure the interface inside the namespace
	if err := m.configureInterfaceInNetns(
		pid,
		vethName,         // old name
		config.Interface, // new name
		config.IPAddress,
		config.MACAddress,
		config.MTU,
		config.Gateway,
	); err != nil {
		return fmt.Errorf("failed to configure interface in netns: %v", err)
	}

	return nil
}

// findPortsForContainer finds all OVS ports associated with a container
func (m *OVSPortManager) findPortsForContainer(ctx context.Context, containerID string) ([]string, error) {
	// Query OVS for interfaces with matching container_id external_id
	var interfaces []Interface
	err := m.ovsClient.WhereCache(func(i *Interface) bool {
		if externalIDs := i.ExternalIDs; externalIDs != nil {
			return externalIDs["container_id"] == containerID
		}
		return false
	}).List(ctx, &interfaces)

	if err != nil {
		return nil, fmt.Errorf("failed to query OVS interfaces: %v", err)
	}

	ports := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		ports = append(ports, iface.Name)
	}

	return ports, nil
}

// cleanupOVSPort removes a port from OVS
func (m *OVSPortManager) cleanupOVSPort(ctx context.Context, bridge, portName string) error {
	// Find the interface by name
	var interfaces []Interface
	err := m.ovsClient.WhereCache(func(i *Interface) bool {
		return i.Name == portName
	}).List(ctx, &interfaces)

	if err != nil {
		return fmt.Errorf("failed to find interface %s: %v", portName, err)
	}

	if len(interfaces) == 0 {
		// Interface doesn't exist, nothing to clean up
		return nil
	}

	iface := interfaces[0]

	// Find the port that contains this interface
	var ports []Port
	err = m.ovsClient.WhereCache(func(p *Port) bool {
		for _, ifaceUUID := range p.Interfaces {
			if ifaceUUID == iface.UUID {
				return true
			}
		}
		return false
	}).List(ctx, &ports)

	if err != nil {
		return fmt.Errorf("failed to find port for interface %s: %v", portName, err)
	}

	if len(ports) == 0 {
		// Port doesn't exist, just delete the interface
		ops, err := m.ovsClient.Where(iface).Delete()
		if err != nil {
			return fmt.Errorf("failed to create delete operation for interface: %v", err)
		}

		_, err = m.ovsClient.Transact(ctx, ops...)
		return err
	}

	port := ports[0]

	// Find the bridge that contains this port
	var bridges []Bridge
	if bridge != "" {
		err = m.ovsClient.WhereCache(func(b *Bridge) bool {
			return b.Name == bridge
		}).List(ctx, &bridges)
	} else {
		err = m.ovsClient.WhereCache(func(b *Bridge) bool {
			for _, portUUID := range b.Ports {
				if portUUID == port.UUID {
					return true
				}
			}
			return false
		}).List(ctx, &bridges)
	}

	if err != nil {
		return fmt.Errorf("failed to find bridge for port %s: %v", portName, err)
	}

	var ops []ovsdb.Operation

	// Remove port from bridge if found
	if len(bridges) > 0 {
		bridgeUpdate := bridges[0]
		var newPorts []string
		for _, portUUID := range bridgeUpdate.Ports {
			if portUUID != port.UUID {
				newPorts = append(newPorts, portUUID)
			}
		}
		bridgeUpdate.Ports = newPorts

		updateOps, err := m.ovsClient.Where(bridges[0]).Update(&bridgeUpdate, &bridgeUpdate)
		if err != nil {
			return fmt.Errorf("failed to create bridge update operation: %v", err)
		}
		ops = append(ops, updateOps...)
	}

	// Delete the port
	deletePortOps, err := m.ovsClient.Where(port).Delete()
	if err != nil {
		return fmt.Errorf("failed to create delete operation for port: %v", err)
	}
	ops = append(ops, deletePortOps...)

	// Delete the interface
	deleteIfaceOps, err := m.ovsClient.Where(iface).Delete()
	if err != nil {
		return fmt.Errorf("failed to create delete operation for interface: %v", err)
	}
	ops = append(ops, deleteIfaceOps...)

	// Execute the transaction
	_, err = m.ovsClient.Transact(ctx, ops...)
	return err
}

// cleanupVethPair removes a veth pair using netlink
func (m *OVSPortManager) cleanupVethPair(portName string) error {
	// Deleting one end of a veth pair automatically deletes the other end
	return m.deleteLinkByName(portName + "_l")
}

// ensureNetnsDirectory ensures the /var/run/netns directory exists
func (m *OVSPortManager) ensureNetnsDirectory() error {
	netnsDir := "/var/run/netns"

	// Check if directory exists
	if _, err := os.Stat(netnsDir); os.IsNotExist(err) {
		// Create directory with proper permissions
		if err := os.MkdirAll(netnsDir, 0755); err != nil {
			return fmt.Errorf("failed to create netns directory %s: %v", netnsDir, err)
		}
		m.logger.WithField("directory", netnsDir).Debug("Created netns directory")
	}

	return nil
}

// createTempNamespaceLink creates a temporary symlink for namespace operations
func (m *OVSPortManager) createTempNamespaceLink(pid int) (string, error) {
	if err := m.ensureNetnsDirectory(); err != nil {
		return "", err
	}

	pidStr := strconv.Itoa(pid)
	nsPath := fmt.Sprintf("/var/run/netns/%s", pidStr)
	procPath := fmt.Sprintf("/proc/%s/ns/net", pidStr)

	// Remove existing link if it exists
	os.Remove(nsPath)

	// Create symlink
	if err := os.Symlink(procPath, nsPath); err != nil {
		return "", fmt.Errorf("failed to create namespace symlink: %v", err)
	}

	m.logger.WithFields(logrus.Fields{
		"pid":       pid,
		"ns_path":   nsPath,
		"proc_path": procPath,
	}).Debug("Created temporary namespace link")

	return nsPath, nil
}

// removeTempNamespaceLink removes a temporary namespace symlink
func (m *OVSPortManager) removeTempNamespaceLink(nsPath string) {
	if err := os.Remove(nsPath); err != nil {
		m.logger.WithError(err).WithField("ns_path", nsPath).Debug("Failed to remove namespace link")
	} else {
		m.logger.WithField("ns_path", nsPath).Debug("Removed temporary namespace link")
	}
}

// checkFileExists checks if a file or directory exists
func (m *OVSPortManager) checkFileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// writeToFile writes content to a file (useful for proc/sys operations)
func (m *OVSPortManager) writeToFile(filepath, content string) error {
	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_TRUNC, 0644)
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
func (m *OVSPortManager) readFromFile(filepath string) (string, error) {
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

func main() {
	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	// Create and start the OVS port manager
	manager, err := NewOVSPortManager()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create OVS port manager")
	}

	if err := manager.Start(ctx); err != nil {
		logrus.WithError(err).Fatal("OVS port manager failed")
	}
}
