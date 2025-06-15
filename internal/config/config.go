package config

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration settings for the OVS Port Manager.
type Config struct {
	// OVS Database settings
	OVS OVSConfig `mapstructure:"ovs"`

	// Docker settings
	Docker DockerConfig `mapstructure:"docker"`

	// Network settings
	Network NetworkConfig `mapstructure:"network"`

	// Logging settings
	Logging LoggingConfig `mapstructure:"logging"`

	// Server settings
	Server ServerConfig `mapstructure:"server"`
}

// OVSConfig contains OVS-specific configuration.
type OVSConfig struct {
	// Database name (default: "Open_vSwitch")
	DatabaseName string `mapstructure:"database_name"`

	// Socket path for OVS database
	SocketPath string `mapstructure:"socket_path"`

	// Connection timeout
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`

	// Default bridge name
	DefaultBridge string `mapstructure:"default_bridge"`

	// Default interface name inside container
	DefaultInterface string `mapstructure:"default_interface"`
}

// DockerConfig contains Docker-specific configuration.
type DockerConfig struct {
	// Socket path for Docker daemon
	SocketPath string `mapstructure:"socket_path"`

	// API version to use
	APIVersion string `mapstructure:"api_version"`

	// Connection timeout
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
}

// ExternalNetworkConfig contains settings for external IP forwarding.
type ExternalNetworkConfig struct {
	// External IP address for the container (e.g., "10.0.0.100/24")
	IPAddress string `mapstructure:"ip_address"`

	// External gateway for the container (e.g., "10.0.0.1")
	Gateway string `mapstructure:"gateway"`

	// Host interface to use for external connectivity (e.g., "eth0")
	// This is the specific interface on the host for external traffic.
	HostInterface string `mapstructure:"host_interface"`

	// Enable IP forwarding on the host
	// This is DEPRECATED. Use NetworkConfig.EnableExternalRouting instead.
	EnableIPForwarding bool `mapstructure:"enable_ip_forwarding"`
}

// NetworkConfig contains network-specific configuration.
type NetworkConfig struct {
	// Default MTU for interfaces
	DefaultMTU int `mapstructure:"default_mtu"`

	// Enable IPv6 support
	EnableIPv6 bool `mapstructure:"enable_ipv6"`

	// Network namespace handling
	HandleNetNS bool `mapstructure:"handle_netns"`

	// EnableExternalRouting globally enables or disables the external routing feature.
	// If false, no external IP routing will be configured, regardless of Docker labels.
	EnableExternalRouting bool `mapstructure:"enable_external_routing"`

	// DefaultExternalInterface is the default host interface to use for external routing
	// if no specific interface is provided via Docker labels. (e.g., "eth0")
	DefaultExternalInterface string `mapstructure:"default_external_interface"`

	// External network configuration for static IP forwarding
	// This section might be deprecated or refactored if settings are moved up.
	External ExternalNetworkConfig `mapstructure:"external"`
}

// GetHostInterfaceName returns the configured host interface name,
// falling back to the default if the provided name is empty.
func (nc *NetworkConfig) GetHostInterfaceName(configuredName string) string {
	if configuredName != "" {
		return configuredName
	}
	return nc.DefaultExternalInterface
}

// LoggingConfig contains logging configuration.
type LoggingConfig struct {
	// Log level (debug, info, warn, error)
	Level string `mapstructure:"level"`

	// Log format (text, json)
	Format string `mapstructure:"format"`

	// Enable structured logging
	Structured bool `mapstructure:"structured"`

	// Log file path (empty for stdout)
	FilePath string `mapstructure:"file_path"`
}

// ServerConfig contains server-specific configuration.
type ServerConfig struct {
	// Enable metrics endpoint
	EnableMetrics bool `mapstructure:"enable_metrics"`

	// Metrics server address
	MetricsAddr string `mapstructure:"metrics_addr"`

	// Enable health check endpoint
	EnableHealthCheck bool `mapstructure:"enable_health_check"`

	// Health check address
	HealthAddr string `mapstructure:"health_addr"`
}

// Load loads configuration from environment variables, config files, and defaults.
func Load() (*Config, error) {
	v := viper.New()

	// Set config name and paths
	v.SetConfigName("ovs-port-manager")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/ovs-port-manager/")
	v.AddConfigPath("$HOME/.ovs-port-manager/")
	v.AddConfigPath("./configs/")
	v.AddConfigPath(".")

	// Set environment variable prefix
	v.SetEnvPrefix("OVS_PORT_MANAGER")
	v.AutomaticEnv()

	// Set defaults
	setDefaults(v)

	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Config file not found, continue with defaults and env vars
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// setDefaults sets default configuration values.
func setDefaults(v *viper.Viper) {
	// OVS defaults
	v.SetDefault("ovs.database_name", getEnvOrDefault("OVS_DB", "Open_vSwitch"))
	v.SetDefault(
		"ovs.socket_path",
		getEnvOrDefault("OVS_SOCKET_PATH", "/var/run/openvswitch/db.sock"),
	)
	v.SetDefault("ovs.connection_timeout", 30*time.Second)
	v.SetDefault("ovs.default_bridge", getEnvOrDefault("OVS_DEFAULT_BRIDGE", "ovs_bond0"))
	v.SetDefault("ovs.default_interface", getEnvOrDefault("OVS_DEFAULT_INTERFACE", "bond0"))

	// Docker defaults
	v.SetDefault(
		"docker.socket_path",
		getEnvOrDefault("DOCKER_SOCKET_PATH", "/var/run/docker.sock"),
	)
	v.SetDefault("docker.api_version", "") // Let the client negotiate
	v.SetDefault("docker.connection_timeout", 30*time.Second)

	// Network defaults
	v.SetDefault("network.default_mtu", 1500)
	v.SetDefault("network.enable_ipv6", getEnvOrDefaultBool("ENABLE_IPV6", false))
	v.SetDefault("network.handle_netns", getEnvOrDefaultBool("HANDLE_NETNS", true))
	v.SetDefault(
		"network.enable_external_routing",
		getEnvOrDefaultBool("ENABLE_EXTERNAL_ROUTING", false),
	)
	v.SetDefault(
		"network.default_external_interface",
		getEnvOrDefault("DEFAULT_EXTERNAL_INTERFACE", ""),
	)

	// External Network defaults (under network.external)
	// Note: network.external.enable_ip_forwarding is deprecated in favor of network.enable_external_routing
	v.SetDefault(
		"network.external.ip_address",
		getEnvOrDefault("EXTERNAL_IP_ADDRESS", ""),
	) // Example, might not be used directly
	v.SetDefault(
		"network.external.gateway",
		getEnvOrDefault("EXTERNAL_GATEWAY", ""),
	) // Example
	v.SetDefault(
		"network.external.host_interface",
		getEnvOrDefault("EXTERNAL_HOST_INTERFACE", ""),
	) // Example
	v.SetDefault(
		"network.external.enable_ip_forwarding",
		getEnvOrDefaultBool("EXTERNAL_ENABLE_IP_FORWARDING", true),
	) // Deprecated

	// Logging defaults
	v.SetDefault("logging.level", getEnvOrDefault("LOG_LEVEL", "info"))
	v.SetDefault("logging.format", getEnvOrDefault("LOG_FORMAT", "text"))
	v.SetDefault("logging.structured", getEnvOrDefaultBool("LOG_STRUCTURED", false))
	v.SetDefault("logging.file_path", getEnvOrDefault("LOG_FILE_PATH", ""))

	// Server defaults
	v.SetDefault("server.enable_metrics", getEnvOrDefaultBool("ENABLE_METRICS", false))
	v.SetDefault("server.metrics_addr", getEnvOrDefault("METRICS_ADDR", ":8080"))
	v.SetDefault("server.enable_health_check", getEnvOrDefaultBool("ENABLE_HEALTH_CHECK", true))
	v.SetDefault("server.health_addr", getEnvOrDefault("HEALTH_ADDR", ":8081"))
}

// getEnvOrDefault gets an environment variable or returns a default value.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvOrDefaultBool gets a boolean environment variable or returns a default value.
// It interprets "true", "1", "yes" as true, and "false", "0", "no" as false (case-insensitive).
func getEnvOrDefaultBool(key string, defaultValue bool) bool {
	valueStr := strings.ToLower(os.Getenv(key))
	if valueStr == "" {
		return defaultValue
	}
	switch valueStr {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		// Log a warning or return default if the value is ambiguous?
		// For now, stick to viper's behavior which might be more nuanced or fallback.
		// However, viper might not be used for these direct env lookups if we are setting defaults before viper reads envs.
		// Let's be explicit for direct os.Getenv calls.
		return defaultValue
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Add validation logic here if needed
	return nil
}
