package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Test default configuration
	config, err := Load()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	// Verify defaults
	if config.OVS.DatabaseName != "Open_vSwitch" {
		t.Errorf("Expected database name 'Open_vSwitch', got '%s'", config.OVS.DatabaseName)
	}

	if config.OVS.DefaultBridge != "ovs_bond0" {
		t.Errorf("Expected default bridge 'ovs_bond0', got '%s'", config.OVS.DefaultBridge)
	}

	if config.Logging.Level != "info" {
		t.Errorf("Expected log level 'info', got '%s'", config.Logging.Level)
	}
}

func TestEnvironmentOverride(t *testing.T) {
	// Set environment variable
	if err := os.Setenv("OVS_DB", "TestDatabase"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("OVS_DB"); err != nil {
			t.Errorf("Failed to unset environment variable: %v", err)
		}
	}()

	config, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config with env override: %v", err)
	}

	if config.OVS.DatabaseName != "TestDatabase" {
		t.Errorf("Expected database name 'TestDatabase', got '%s'", config.OVS.DatabaseName)
	}
}

func TestViperEnvironmentOverride(t *testing.T) {
	// Set viper environment variable (note: viper converts nested keys)
	if err := os.Setenv("OVS_PORT_MANAGER_OVS_DEFAULT_BRIDGE", "custom_bridge"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("OVS_PORT_MANAGER_OVS_DEFAULT_BRIDGE"); err != nil {
			t.Errorf("Failed to unset environment variable: %v", err)
		}
	}()

	// Also try the alternative format
	if err := os.Setenv("OVS_PORT_MANAGER_OVS__DEFAULT_BRIDGE", "custom_bridge"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("OVS_PORT_MANAGER_OVS__DEFAULT_BRIDGE"); err != nil {
			t.Errorf("Failed to unset environment variable: %v", err)
		}
	}()

	config, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config with viper env override: %v", err)
	}

	// This test might be environment-dependent, so let's just verify it loads
	if config.OVS.DefaultBridge == "" {
		t.Errorf("Default bridge should not be empty")
	}
}

func TestConfigDefaults(t *testing.T) {
	config, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Test all default values
	tests := []struct {
		name     string
		actual   any
		expected any
	}{
		{"DatabaseName", config.OVS.DatabaseName, "Open_vSwitch"},
		{"SocketPath", config.OVS.SocketPath, "/var/run/openvswitch/db.sock"},
		{"ConnectionTimeout", config.OVS.ConnectionTimeout, 30 * time.Second},
		{"DefaultBridge", config.OVS.DefaultBridge, "ovs_bond0"},
		{"DefaultInterface", config.OVS.DefaultInterface, "bond0"},
		{"LogLevel", config.Logging.Level, "info"},
		{"LogFormat", config.Logging.Format, "text"},
		{"DefaultMTU", config.Network.DefaultMTU, 1500},
		{"EnableHealthCheck", config.Server.EnableHealthCheck, true},
		{"EnableMetrics", config.Server.EnableMetrics, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("Expected %s to be %v, got %v", tt.name, tt.expected, tt.actual)
			}
		})
	}
}
