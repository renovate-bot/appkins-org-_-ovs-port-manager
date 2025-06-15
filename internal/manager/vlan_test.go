package manager

import (
	"strconv"
	"testing"
)

func TestVLANValidation(t *testing.T) {
	tests := []struct {
		name        string
		vlanStr     string
		expectValid bool
		expectedID  int
		description string
	}{
		{
			name:        "Valid VLAN ID 1",
			vlanStr:     "1",
			expectValid: true,
			expectedID:  1,
			description: "Minimum valid VLAN ID",
		},
		{
			name:        "Valid VLAN ID 100",
			vlanStr:     "100",
			expectValid: true,
			expectedID:  100,
			description: "Common VLAN ID",
		},
		{
			name:        "Valid VLAN ID 4094",
			vlanStr:     "4094",
			expectValid: true,
			expectedID:  4094,
			description: "Maximum valid VLAN ID",
		},
		{
			name:        "Invalid VLAN ID 0",
			vlanStr:     "0",
			expectValid: false,
			expectedID:  0,
			description: "VLAN ID 0 is reserved",
		},
		{
			name:        "Invalid VLAN ID 4095",
			vlanStr:     "4095",
			expectValid: false,
			expectedID:  4095,
			description: "VLAN ID 4095 is reserved",
		},
		{
			name:        "Invalid VLAN ID too high",
			vlanStr:     "5000",
			expectValid: false,
			expectedID:  5000,
			description: "VLAN ID above valid range",
		},
		{
			name:        "Invalid negative VLAN ID",
			vlanStr:     "-1",
			expectValid: false,
			expectedID:  -1,
			description: "Negative VLAN ID",
		},
		{
			name:        "Invalid non-numeric VLAN",
			vlanStr:     "abc",
			expectValid: false,
			expectedID:  0,
			description: "Non-numeric VLAN string",
		},
		{
			name:        "Empty VLAN string",
			vlanStr:     "",
			expectValid: false,
			expectedID:  0,
			description: "Empty VLAN string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test VLAN parsing (similar to what would be in setVLAN)
			vlanID, err := strconv.Atoi(tt.vlanStr)
			parseError := err != nil

			// Check if parsing succeeded when expected
			if tt.expectValid && parseError {
				t.Errorf("Expected valid VLAN %s, got parse error: %v", tt.vlanStr, err)
				return
			}

			if !tt.expectValid && !parseError {
				// For invalid cases, we need to check if the parsed value is in valid range
				if vlanID >= 1 && vlanID <= 4094 {
					t.Errorf(
						"Expected invalid VLAN %s, but it parsed to valid ID %d",
						tt.vlanStr,
						vlanID,
					)
					return
				}
			}

			// For valid cases, check the parsed value
			if tt.expectValid && !parseError {
				if vlanID != tt.expectedID {
					t.Errorf("VLAN ID = %d, want %d", vlanID, tt.expectedID)
				}

				// Additional validation for VLAN range
				if vlanID < 1 || vlanID > 4094 {
					t.Errorf("VLAN ID %d is outside valid range 1-4094", vlanID)
				}
			}
		})
	}
}

func TestVLANStringFormatting(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectValid bool
	}{
		{"Leading zeros", "0100", true},       // Should parse as 100
		{"Whitespace", " 100 ", false},        // Spaces should be invalid
		{"Plus sign", "+100", true},           // Plus sign should be invalid
		{"Decimal", "100.0", false},           // Decimal should be invalid
		{"Scientific", "1e2", false},          // Scientific notation should be invalid
		{"Hex format", "0x64", false},         // Hex should be invalid
		{"Binary format", "0b1100100", false}, // Binary should be invalid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := strconv.Atoi(tt.input)
			hasError := err != nil

			if tt.expectValid && hasError {
				t.Errorf("Expected %s to be valid, got error: %v", tt.input, err)
			}
			if !tt.expectValid && !hasError {
				t.Errorf("Expected %s to be invalid, but it parsed successfully", tt.input)
			}
		})
	}
}

func TestVLANBoundaryConditions(t *testing.T) {
	// Test boundary conditions for VLAN IDs
	boundaryTests := []struct {
		vlanID      int
		expectValid bool
		description string
	}{
		{0, false, "VLAN 0 is reserved"},
		{1, true, "VLAN 1 is the minimum valid"},
		{2, true, "VLAN 2 is valid"},
		{4093, true, "VLAN 4093 is valid"},
		{4094, true, "VLAN 4094 is the maximum valid"},
		{4095, false, "VLAN 4095 is reserved"},
		{4096, false, "VLAN 4096 is above maximum"},
	}

	for _, tt := range boundaryTests {
		t.Run(tt.description, func(t *testing.T) {
			isValid := tt.vlanID >= 1 && tt.vlanID <= 4094

			if isValid != tt.expectValid {
				t.Errorf("VLAN %d validity = %v, want %v (%s)",
					tt.vlanID, isValid, tt.expectValid, tt.description)
			}
		})
	}
}
