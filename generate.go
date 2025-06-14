//go:build ignore

// This file contains go:generate directives for code generation
package main

//go:generate go tool modelgen -p models -o ./internal/models ./assets/ovs-nb.ovsschema
