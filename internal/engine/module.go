package engine

import (
	"context"

	"github.com/jclement/tripline/pkg/finding"
)

// Module is the interface that all Trapline scanner modules must implement.
// Each module represents a distinct security scanning capability (e.g., file integrity
// checking, open port detection, user account auditing). The engine treats modules
// as opaque scanners: it handles scheduling, enrichment, and deduplication, while
// each module owns the logic for detecting changes in its domain.
//
// Concurrency contract: the engine guarantees that for a given module instance,
// Init is called exactly once before any calls to Scan or Rebaseline. However,
// Scan and Rebaseline may be called from different goroutines (e.g., a daemon
// scan tick vs. a CLI rebaseline command), so implementations should be safe for
// concurrent use if they share mutable state.
type Module interface {
	// Name returns the unique, stable identifier for this module (e.g.,
	// "file-integrity", "open-ports", "users"). This name is used as:
	//   - The key in the configuration file's modules map.
	//   - The module field stamped onto every finding for attribution.
	//   - The key in the cooldown/deduplication map (combined with FindingID).
	//   - The label in metrics collection.
	// The returned value must be constant across calls and must not be empty.
	Name() string

	// Init is called once during engine initialization to prepare the module
	// for scanning. The ModuleConfig provides:
	//   - StateDir: a directory where the module can persist state files.
	//   - BaselinesDir: a subdirectory specifically for baseline snapshots.
	//   - Settings: the module-specific key-value pairs from the YAML config.
	//
	// Init should validate its configuration, create any required directories
	// or files, and load the current baseline (if any). If Init returns a
	// non-nil error, the engine aborts startup and does not call Scan or
	// Rebaseline on any module.
	Init(cfg ModuleConfig) error

	// Scan performs one complete scan cycle and returns any findings that
	// represent deviations from the known-good baseline. The returned slice
	// may be empty (no changes detected) or nil. Each Finding must have at
	// minimum a FindingID that is stable across scans for the same underlying
	// issue -- the engine uses Module name + FindingID for deduplication.
	//
	// The context should be respected for cancellation: long-running scans
	// should periodically check ctx.Done() and return early with an error
	// if the context is cancelled.
	//
	// Scan must not modify the baseline. It is a read-only operation that
	// compares current state against the stored baseline.
	Scan(ctx context.Context) ([]finding.Finding, error)

	// Rebaseline captures the current system state as the new known-good
	// baseline. After a successful Rebaseline call, subsequent Scan calls
	// will compare against this new snapshot rather than the previous one.
	//
	// This is typically invoked by an operator after they have reviewed and
	// accepted the current findings (e.g., after deploying a legitimate
	// configuration change). The context should be respected for cancellation.
	//
	// Rebaseline must be idempotent: calling it multiple times in succession
	// without intervening state changes should produce the same baseline.
	Rebaseline(ctx context.Context) error
}

// ModuleConfig holds the configuration and filesystem paths provided to a module
// during initialization. It is constructed by the engine from the global config
// and passed to Module.Init.
type ModuleConfig struct {
	// Settings is the raw module-specific configuration map parsed from the
	// YAML config file. Keys and values are arbitrary and defined by each
	// module. For example, the file-integrity module might expect a "paths"
	// key containing a list of directories to monitor. This may be nil if
	// the config file has no section for this module.
	Settings map[string]interface{}

	// StateDir is the top-level directory where the module may read and write
	// persistent state files (e.g., hash databases, scan caches). The engine
	// ensures this directory exists before calling Init.
	StateDir string

	// BaselinesDir is a subdirectory of StateDir specifically designated for
	// baseline snapshot files. Modules should store their known-good state
	// here so that Scan can compare current state against the baseline.
	BaselinesDir string
}
