package config

import (
	"os"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration settings for the OVS Port Manager
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

// OVSConfig contains OVS-specific configuration
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

// DockerConfig contains Docker-specific configuration
type DockerConfig struct {
	// Socket path for Docker daemon
	SocketPath string `mapstructure:"socket_path"`

	// API version to use
	APIVersion string `mapstructure:"api_version"`

	// Connection timeout
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
}

// NetworkConfig contains network-specific configuration
type NetworkConfig struct {
	// Default MTU for interfaces
	DefaultMTU int `mapstructure:"default_mtu"`

	// Enable IPv6 support
	EnableIPv6 bool `mapstructure:"enable_ipv6"`

	// Network namespace handling
	HandleNetNS bool `mapstructure:"handle_netns"`
}

// LoggingConfig contains logging configuration
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

// ServerConfig contains server-specific configuration
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

// Load loads configuration from environment variables, config files, and defaults
func Load() (*Config, error) {
	v := viper.New()

	// Set config name and paths
	v.SetConfigName("ovs-port-manager")
	v.SetConfigType("yaml")
	v.AddConfigPath("/etc/ovs-port-manager/")
	v.AddConfigPath("$HOME/.ovs-port-manager/")
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

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// OVS defaults
	v.SetDefault("ovs.database_name", getEnvOrDefault("OVS_DB", "Open_vSwitch"))
	v.SetDefault("ovs.socket_path", getEnvOrDefault("OVS_SOCKET_PATH", "/var/run/openvswitch/db.sock"))
	v.SetDefault("ovs.connection_timeout", 30*time.Second)
	v.SetDefault("ovs.default_bridge", getEnvOrDefault("OVS_DEFAULT_BRIDGE", "ovs_bond0"))
	v.SetDefault("ovs.default_interface", getEnvOrDefault("OVS_DEFAULT_INTERFACE", "bond0"))

	// Docker defaults
	v.SetDefault("docker.socket_path", getEnvOrDefault("DOCKER_SOCKET_PATH", "/var/run/docker.sock"))
	v.SetDefault("docker.api_version", "")
	v.SetDefault("docker.connection_timeout", 30*time.Second)

	// Network defaults
	v.SetDefault("network.default_mtu", 1500)
	v.SetDefault("network.enable_ipv6", false)
	v.SetDefault("network.handle_netns", true)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")
	v.SetDefault("logging.structured", false)
	v.SetDefault("logging.file_path", "")

	// Server defaults
	v.SetDefault("server.enable_metrics", false)
	v.SetDefault("server.metrics_addr", ":8080")
	v.SetDefault("server.enable_health_check", true)
	v.SetDefault("server.health_addr", ":8081")
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Add validation logic here if needed
	return nil
}
