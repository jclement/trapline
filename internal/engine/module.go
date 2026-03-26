package engine

import (
	"context"

	"github.com/jclement/tripline/pkg/finding"
)

// Module is the interface that all scanner modules implement.
type Module interface {
	// Name returns the module identifier (e.g., "file-integrity").
	Name() string

	// Init is called once at startup with the module's config section.
	Init(cfg ModuleConfig) error

	// Scan runs one scan cycle. Returns findings (may be empty).
	Scan(ctx context.Context) ([]finding.Finding, error)

	// Rebaseline captures current state as the new known-good baseline.
	Rebaseline(ctx context.Context) error
}

// ModuleConfig holds the configuration and state store for a module.
type ModuleConfig struct {
	// Settings is the raw module config map from the YAML.
	Settings map[string]interface{}
	// StateDir is the directory for baseline/state files.
	StateDir string
	// BaselinesDir is specifically for baseline files.
	BaselinesDir string
}
