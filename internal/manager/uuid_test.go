package manager

import (
	"testing"

	"github.com/google/uuid"
)

func TestUUIDGeneration(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		prefix    string
		checkFunc func(string) bool
	}{
		{
			name:   "Interface UUID generation",
			input:  "test123_l",
			prefix: "interface:",
			checkFunc: func(uuidStr string) bool {
				// Check if it's a valid UUID format
				_, err := uuid.Parse(uuidStr)
				return err == nil
			},
		},
		{
			name:   "Port UUID generation",
			input:  "test123_l",
			prefix: "port:",
			checkFunc: func(uuidStr string) bool {
				// Check if it's a valid UUID format
				_, err := uuid.Parse(uuidStr)
				return err == nil
			},
		},
		{
			name:   "Deterministic generation",
			input:  "same-input",
			prefix: "test:",
			checkFunc: func(uuidStr string) bool {
				// Generate the same UUID again and compare
				uuid2 := uuid.NewSHA1(ovsPortManagerNamespace, []byte("test:same-input"))
				return uuidStr == uuid2.String()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate UUID using the same method as in the code
			generatedUUID := uuid.NewSHA1(ovsPortManagerNamespace, []byte(tt.prefix+tt.input))
			uuidStr := generatedUUID.String()

			// Check if UUID is valid format
			if !tt.checkFunc(uuidStr) {
				t.Errorf("UUID validation failed for input %s: %s", tt.input, uuidStr)
			}

			// Check UUID string format (should be 36 characters with hyphens)
			if len(uuidStr) != 36 {
				t.Errorf("UUID length = %d, want 36", len(uuidStr))
			}

			// Check hyphen positions
			expectedHyphens := []int{8, 13, 18, 23}
			for _, pos := range expectedHyphens {
				if uuidStr[pos] != '-' {
					t.Errorf("Expected hyphen at position %d in UUID %s", pos, uuidStr)
				}
			}

			// Check that all other characters are hex digits
			for i, char := range uuidStr {
				if i == 8 || i == 13 || i == 18 || i == 23 {
					continue // Skip hyphens
				}
				if !((char >= '0' && char <= '9') ||
					(char >= 'a' && char <= 'f') ||
					(char >= 'A' && char <= 'F')) {
					t.Errorf(
						"Invalid hex character '%c' at position %d in UUID %s",
						char,
						i,
						uuidStr,
					)
				}
			}
		})
	}
}

func TestUUIDConsistency(t *testing.T) {
	// Test that the same input always generates the same UUID
	testInputs := []string{
		"interface:test123_l",
		"port:test123_l",
		"interface:container456_l",
		"port:container456_l",
	}

	for _, input := range testInputs {
		t.Run("Consistency_"+input, func(t *testing.T) {
			uuid1 := uuid.NewSHA1(ovsPortManagerNamespace, []byte(input))
			uuid2 := uuid.NewSHA1(ovsPortManagerNamespace, []byte(input))
			uuid3 := uuid.NewSHA1(ovsPortManagerNamespace, []byte(input))

			if uuid1.String() != uuid2.String() || uuid2.String() != uuid3.String() {
				t.Errorf("UUID generation not consistent for input %s: %s, %s, %s",
					input, uuid1.String(), uuid2.String(), uuid3.String())
			}
		})
	}
}

func TestUUIDUniqueness(t *testing.T) {
	// Test that different inputs generate different UUIDs
	testInputs := []string{
		"interface:test1_l",
		"interface:test2_l",
		"port:test1_l",
		"port:test2_l",
		"interface:different_l",
		"port:different_l",
	}

	generatedUUIDs := make(map[string]string)

	for _, input := range testInputs {
		uuid := uuid.NewSHA1(ovsPortManagerNamespace, []byte(input))
		uuidStr := uuid.String()

		if existingInput, exists := generatedUUIDs[uuidStr]; exists {
			t.Errorf("UUID collision: inputs '%s' and '%s' both generated UUID %s",
				input, existingInput, uuidStr)
		}
		generatedUUIDs[uuidStr] = input
	}
}

func TestUUIDNamespaceUsage(t *testing.T) {
	// Test that our namespace UUID is valid and consistent
	namespaceStr := ovsPortManagerNamespace.String()

	// Check that namespace is a valid UUID
	parsedNS, err := uuid.Parse(namespaceStr)
	if err != nil {
		t.Errorf("ovsPortManagerNamespace is not a valid UUID: %v", err)
	}

	// Check that it matches our expected namespace
	expectedNS := "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	if namespaceStr != expectedNS {
		t.Errorf("ovsPortManagerNamespace = %s, want %s", namespaceStr, expectedNS)
	}

	// Check that namespace UUID is consistent
	if parsedNS.String() != ovsPortManagerNamespace.String() {
		t.Errorf("Namespace UUID not consistent after parsing")
	}
}

func TestUUIDPrefixHandling(t *testing.T) {
	// Test different prefix patterns
	baseName := "test123_l"

	tests := []struct {
		prefix   string
		expected string
	}{
		{"interface:", "interface:test123_l"},
		{"port:", "port:test123_l"},
		{"", "test123_l"},
		{"custom:", "custom:test123_l"},
	}

	for _, tt := range tests {
		t.Run("Prefix_"+tt.prefix, func(t *testing.T) {
			input := tt.prefix + baseName
			if input != tt.expected {
				t.Errorf("Input construction: got %s, want %s", input, tt.expected)
			}

			// Generate UUID and verify it's valid
			generatedUUID := uuid.NewSHA1(ovsPortManagerNamespace, []byte(input))
			uuidStr := generatedUUID.String()

			_, err := uuid.Parse(uuidStr)
			if err != nil {
				t.Errorf("Generated UUID is invalid: %v", err)
			}
		})
	}
}

func TestUUIDVersionAndVariant(t *testing.T) {
	// Test that generated UUIDs have correct version and variant
	testInput := "interface:test_l"
	generatedUUID := uuid.NewSHA1(ovsPortManagerNamespace, []byte(testInput))

	// SHA1-based UUIDs should be version 5
	version := generatedUUID.Version()
	if version != 5 {
		t.Errorf("UUID version = %d, want 5 (SHA1-based)", version)
	}

	// Check variant (should be RFC 4122)
	variant := generatedUUID.Variant()
	if variant != uuid.RFC4122 {
		t.Errorf("UUID variant = %v, want RFC4122", variant)
	}
}
