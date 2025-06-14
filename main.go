package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/digitalocean/go-openvswitch/ovs"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"
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
	DefaultBridge = "ovsbr0"
	// DefaultInterface is the default interface name inside container
	DefaultInterface = "eth1"
)

// OVSPortManager manages OVS ports for Docker containers
type OVSPortManager struct {
	dockerClient *client.Client
	ovsClient    *ovs.Client
	logger       *logrus.Logger
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
	// Create Docker client
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	// Create OVS client with sudo privileges (typically required for OVS operations)
	ovsClient := ovs.New(ovs.Sudo())

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	return &OVSPortManager{
		dockerClient: dockerClient,
		ovsClient:    ovsClient,
		logger:       logger,
	}, nil
}

// Start begins monitoring Docker events and managing OVS ports
func (m *OVSPortManager) Start(ctx context.Context) error {
	m.logger.Info("Starting OVS Port Manager...")

	// Ensure default bridge exists
	if err := m.ensureDefaultBridge(); err != nil {
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
func (m *OVSPortManager) ensureDefaultBridge() error {
	bridges, err := m.ovsClient.VSwitch.ListBridges()
	if err != nil {
		return fmt.Errorf("failed to list bridges: %v", err)
	}

	for _, bridge := range bridges {
		if bridge == DefaultBridge {
			m.logger.WithField("bridge", DefaultBridge).Info("Default bridge already exists")
			return nil
		}
	}

	m.logger.WithField("bridge", DefaultBridge).Info("Creating default bridge")
	if err := m.ovsClient.VSwitch.AddBridge(DefaultBridge); err != nil {
		return fmt.Errorf("failed to create bridge %s: %v", DefaultBridge, err)
	}

	return nil
}

// processExistingContainers processes all running containers that have OVS labels
func (m *OVSPortManager) processExistingContainers(ctx context.Context) error {
	containers, err := m.dockerClient.ContainerList(ctx, types.ContainerListOptions{
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
		bridge = DefaultBridge
	}

	return &ContainerOVSConfig{
		ContainerID: containerID,
		IPAddress:   ipAddress,
		Bridge:      bridge,
		Gateway:     labels[OVSGatewayLabel],
		MTU:         labels[OVSMTULabel],
		MACAddress:  labels[OVSMACAddressLabel],
		Interface:   DefaultInterface,
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
	if exists, err := m.portExists(config.Bridge, config.ContainerID, config.Interface); err != nil {
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
	if err := m.addPortToBridge(config.Bridge, portName+"_l", config.ContainerID, config.Interface); err != nil {
		m.cleanupVethPair(portName)
		return fmt.Errorf("failed to add port to bridge: %v", err)
	}

	// Move container-side interface to container namespace and configure it
	if err := m.configureContainerInterface(container.State.Pid, portName+"_c", config); err != nil {
		m.cleanupOVSPort(config.Bridge, portName+"_l")
		m.cleanupVethPair(portName)
		return fmt.Errorf("failed to configure container interface: %v", err)
	}

	m.logger.WithField("container_id", config.ContainerID[:12]).Info("Successfully added OVS port")
	return nil
}

// removeOVSPort removes OVS ports for a container
func (m *OVSPortManager) removeOVSPort(ctx context.Context, containerID string) error {
	// Find all ports for this container
	ports, err := m.findPortsForContainer(containerID)
	if err != nil {
		return fmt.Errorf("failed to find ports for container: %v", err)
	}

	for _, port := range ports {
		m.logger.WithFields(logrus.Fields{
			"container_id": containerID[:12],
			"port":         port,
		}).Info("Removing OVS port")

		if err := m.cleanupOVSPort("", port); err != nil {
			m.logger.WithError(err).WithField("port", port).Error("Failed to cleanup OVS port")
		}

		if err := m.cleanupVethPair(strings.TrimSuffix(port, "_l")); err != nil {
			m.logger.WithError(err).WithField("port", port).Error("Failed to cleanup veth pair")
		}
	}

	return nil
}

// portExists checks if a port already exists for the container and interface
func (m *OVSPortManager) portExists(bridge, containerID, interfaceName string) (bool, error) {
	// Check if there's already an interface for this container and interface name
	cmd := exec.Command("ovs-vsctl", "--columns=name", "--format=csv", "--no-headings", "--data=bare", 
		"find", "interface", 
		fmt.Sprintf("external_ids:container_id=%s", containerID),
		fmt.Sprintf("external_ids:container_iface=%s", interfaceName))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("failed to query OVS interfaces: %v", err)
	}
	
	return strings.TrimSpace(string(output)) != "", nil
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

// createVethPair creates a veth pair for the container
func (m *OVSPortManager) createVethPair(portName string) error {
	// ip link add ${PORTNAME}_l type veth peer name ${PORTNAME}_c
	return m.runCommand("ip", "link", "add", portName+"_l", "type", "veth", "peer", "name", portName+"_c")
}

// addPortToBridge adds the bridge-side veth interface to the OVS bridge
func (m *OVSPortManager) addPortToBridge(bridge, portName, containerID, interfaceName string) error {
	// Add port to bridge
	if err := m.ovsClient.VSwitch.AddPort(bridge, portName); err != nil {
		return err
	}

	// Set external IDs to track the container and interface
	// ovs-vsctl set interface ${PORTNAME}_l external_ids:container_id=${CONTAINER} external_ids:container_iface=${INTERFACE}
	args := []string{
		"set", "interface", portName,
		fmt.Sprintf("external_ids:container_id=%s", containerID),
		fmt.Sprintf("external_ids:container_iface=%s", interfaceName),
	}
	
	if err := m.runOVSCommand(args...); err != nil {
		return err
	}

	// Bring up the bridge-side interface
	return m.runCommand("ip", "link", "set", portName, "up")
}

// configureContainerInterface moves and configures the container-side interface
func (m *OVSPortManager) configureContainerInterface(pid int, vethName string, config *ContainerOVSConfig) error {
	pidStr := fmt.Sprintf("%d", pid)
	
	// Create netns link
	if err := m.runCommand("mkdir", "-p", "/var/run/netns"); err != nil {
		return err
	}
	
	nsPath := fmt.Sprintf("/var/run/netns/%s", pidStr)
	procPath := fmt.Sprintf("/proc/%s/ns/net", pidStr)
	
	if err := m.runCommand("ln", "-sf", procPath, nsPath); err != nil {
		return err
	}
	
	// Ensure cleanup of netns link
	defer m.runCommand("rm", "-f", nsPath)

	// Move interface to container namespace
	if err := m.runCommand("ip", "link", "set", vethName, "netns", pidStr); err != nil {
		return err
	}

	// Rename interface inside container
	if err := m.runCommand("ip", "netns", "exec", pidStr, "ip", "link", "set", "dev", vethName, "name", config.Interface); err != nil {
		return err
	}

	// Bring up the interface
	if err := m.runCommand("ip", "netns", "exec", pidStr, "ip", "link", "set", config.Interface, "up"); err != nil {
		return err
	}

	// Configure IP address
	if config.IPAddress != "" {
		if err := m.runCommand("ip", "netns", "exec", pidStr, "ip", "addr", "add", config.IPAddress, "dev", config.Interface); err != nil {
			return err
		}
	}

	// Configure MAC address if specified
	if config.MACAddress != "" {
		if err := m.runCommand("ip", "netns", "exec", pidStr, "ip", "link", "set", "dev", config.Interface, "address", config.MACAddress); err != nil {
			return err
		}
	}

	// Configure MTU if specified
	if config.MTU != "" {
		if err := m.runCommand("ip", "netns", "exec", pidStr, "ip", "link", "set", "dev", config.Interface, "mtu", config.MTU); err != nil {
			return err
		}
	}

	// Configure gateway if specified
	if config.Gateway != "" {
		if err := m.runCommand("ip", "netns", "exec", pidStr, "ip", "route", "add", "default", "via", config.Gateway); err != nil {
			return err
		}
	}

	return nil
}

// findPortsForContainer finds all OVS ports associated with a container
func (m *OVSPortManager) findPortsForContainer(containerID string) ([]string, error) {
	// Query OVS for interfaces with matching container_id external_id
	cmd := exec.Command("ovs-vsctl", "--columns=name", "--format=csv", "--no-headings", "--data=bare", 
		"find", "interface", fmt.Sprintf("external_ids:container_id=%s", containerID))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query OVS interfaces: %v", err)
	}
	
	ports := []string{}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			ports = append(ports, line)
		}
	}
	
	return ports, nil
}

// cleanupOVSPort removes a port from OVS
func (m *OVSPortManager) cleanupOVSPort(bridge, port string) error {
	if bridge != "" {
		return m.ovsClient.VSwitch.DeletePort(bridge, port)
	}
	
	// If bridge is unknown, use ovs-vsctl to delete the port
	return m.runOVSCommand("--if-exists", "del-port", port)
}

// cleanupVethPair removes a veth pair
func (m *OVSPortManager) cleanupVethPair(portName string) error {
	return m.runCommand("ip", "link", "delete", portName+"_l")
}

// runCommand executes a system command
func (m *OVSPortManager) runCommand(name string, args ...string) error {
	m.logger.WithFields(logrus.Fields{
		"command": name,
		"args":    args,
	}).Debug("Executing command")
	
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.WithFields(logrus.Fields{
			"command": name,
			"args":    args,
			"output":  string(output),
		}).Error("Command failed")
		return fmt.Errorf("command %s failed: %v, output: %s", name, err, string(output))
	}
	
	if len(output) > 0 {
		m.logger.WithFields(logrus.Fields{
			"command": name,
			"output":  string(output),
		}).Debug("Command output")
	}
	
	return nil
}

// runOVSCommand executes an ovs-vsctl command
func (m *OVSPortManager) runOVSCommand(args ...string) error {
	m.logger.WithFields(logrus.Fields{
		"command": "ovs-vsctl",
		"args":    args,
	}).Debug("Executing OVS command")
	
	cmd := exec.Command("ovs-vsctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		m.logger.WithFields(logrus.Fields{
			"command": "ovs-vsctl",
			"args":    args,
			"output":  string(output),
		}).Error("OVS command failed")
		return fmt.Errorf("ovs-vsctl command failed: %v, output: %s", err, string(output))
	}
	
	if len(output) > 0 {
		m.logger.WithFields(logrus.Fields{
			"command": "ovs-vsctl",
			"output":  string(output),
		}).Debug("OVS command output")
	}
	
	return nil
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
