// Package suid monitors the filesystem for SUID and SGID binaries, detecting
// new, unexpected, or removed setuid/setgid files by comparing against a
// stored baseline.
//
// # What it monitors and why
//
// SUID (Set User ID) and SGID (Set Group ID) binaries execute with the
// privileges of the file owner or group rather than the calling user. This is
// a classic and well-understood privilege escalation vector. Attackers who gain
// unprivileged shell access commonly set the SUID bit on /bin/bash or drop a
// custom SUID binary to maintain persistent root access. A healthy Linux system
// has a small, well-known set of SUID binaries (sudo, passwd, ping, etc.);
// any deviation from this set is a strong signal of compromise or misconfiguration.
//
// # How it works
//
//  1. On first scan, the module walks configured directories and records every file
//     with the SUID or SGID bit set. This becomes the baseline (persisted as JSON).
//
//  2. On subsequent scans, it performs a fresh walk and compares against the baseline:
//     - New SUID/SGID files that were not in the baseline produce a finding.
//     - Baseline entries that no longer exist produce a removal finding.
//
//  3. The severity is context-dependent: SUID files appearing in /tmp or /var/tmp
//     are flagged as CRITICAL because these are world-writable directories where
//     legitimate SUID binaries should never exist.
//
// Data sources: filesystem stat() calls via filepath.Walk over configurable root
// directories. No external commands are invoked.
//
// # What it catches
//
//   - Attacker-placed SUID shells (chmod u+s /bin/bash, custom ELF in /tmp)
//   - Backdoor SUID binaries dropped for persistence
//   - Unauthorized package installations that add unexpected SUID binaries
//   - Removal of expected SUID binaries (potential anti-forensics or broken system)
//   - MITRE ATT&CK: T1548.001 (Abuse Elevation Control Mechanism: SUID/SGID),
//     T1546 (Event Triggered Execution via SGID), T1222.002 (File and Directory
//     Permissions Modification: Linux)
//
// # What it does NOT catch (known limitations)
//
//   - Does not verify the content/hash of SUID binaries — a legitimate SUID binary
//     could be replaced with a trojanized version without changing its permissions.
//     Use the packages module for content integrity checks.
//   - Does not scan all filesystems by default — only /usr, /bin, /sbin, /opt.
//     Attacker SUID binaries in /home or custom mount points will be missed unless
//     scan_paths is configured to include them.
//   - Does not detect SUID binaries on network filesystems (NFS with root_squash
//     may hide them; nosuid mounts neutralize the threat but the file still exists).
//   - Linux capabilities (setcap) provide equivalent privilege escalation but are
//     NOT detected by this module — that would require a separate capabilities scanner.
//   - First-scan baseline is trusted implicitly. If the system is already
//     compromised when Trapline is first deployed, attacker SUID binaries will be
//     accepted into the baseline.
//
// # False positive risks
//
//   - Package updates (apt upgrade) may add or remove legitimate SUID binaries.
//     Rebaseline after planned maintenance to suppress these.
//   - Snap/Flatpak installations can introduce SUID helpers. The default exclude
//     list skips /snap, but other package managers may need exclusions.
//   - Docker overlay filesystems can surface SUID files from images; /var/lib/docker
//     is excluded by default for this reason.
//
// # Performance characteristics
//
// Performs a full filesystem walk of the configured scan paths on every scan.
// On a typical server with ~50,000 files in /usr, this takes 1-3 seconds. The
// walk is context-aware and will abort promptly on cancellation. Excluded paths
// use filepath.SkipDir to avoid descending into expensive subtrees.
//
// # Configuration options
//
// Via engine.ModuleConfig.Settings:
//
//   - "scan_paths" ([]string): Override the default root directories to walk.
//     Default: ["/usr", "/bin", "/sbin", "/opt"]
//   - "exclude_paths" ([]string): Override the default exclusion prefixes.
//     Default: ["/proc", "/sys", "/dev", "/var/lib/docker", "/snap"]
package suid

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// SuidEntry records a single SUID/SGID file's path and permission mode.
// The mode is stored so that future enhancements could detect mode changes
// (e.g., a file gaining SUID that previously only had SGID).
type SuidEntry struct {
	Path string      `json:"path"`
	Mode os.FileMode `json:"mode"`
}

// SuidBaseline stores the complete set of known SUID/SGID files.
// Initialized is tracked explicitly because an empty Entries map is valid
// (a minimal system could legitimately have no SUID binaries in the scan paths).
type SuidBaseline struct {
	Initialized bool                 `json:"initialized"`
	Entries     map[string]SuidEntry `json:"entries"`
}

// Module implements engine.Scanner for SUID/SGID binary monitoring.
type Module struct {
	store        *baseline.Store
	baseline     SuidBaseline
	scanPaths    []string // Root directories to walk for SUID/SGID files
	excludePaths []string // Path prefixes to skip (performance and noise reduction)
}

// New creates a SUID scanner with default scan and exclude paths. The defaults
// cover standard Linux binary locations while skipping virtual filesystems and
// container overlay storage that would produce noise or performance issues.
func New() *Module {
	return &Module{
		scanPaths:    []string{"/usr", "/bin", "/sbin", "/opt"},
		excludePaths: []string{"/proc", "/sys", "/dev", "/var/lib/docker", "/snap"},
	}
}

func (m *Module) Name() string { return "suid" }

// Init loads the baseline store and applies any user-provided configuration
// overrides for scan paths and exclusions. The Entries map is defensively
// initialized because JSON deserialization of a null map would leave it nil,
// which would cause panics on subsequent map access.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baseline = SuidBaseline{Entries: make(map[string]SuidEntry)}
	m.store.Load(m.Name(), &m.baseline)
	// Defensive nil check: JSON unmarshal of {"entries": null} leaves map nil
	if m.baseline.Entries == nil {
		m.baseline.Entries = make(map[string]SuidEntry)
	}

	// Allow users to override which directories are scanned for SUID binaries.
	// This is important for non-standard Linux layouts or systems with binaries
	// in unusual locations (e.g., /opt/custom/bin).
	if paths, ok := cfg.Settings["scan_paths"]; ok {
		if ps, ok := paths.([]interface{}); ok {
			m.scanPaths = nil
			for _, p := range ps {
				if s, ok := p.(string); ok {
					m.scanPaths = append(m.scanPaths, s)
				}
			}
		}
	}

	// Allow users to add exclusion prefixes to skip directories that produce
	// false positives or are too expensive to walk (e.g., large NFS mounts).
	if paths, ok := cfg.Settings["exclude_paths"]; ok {
		if ps, ok := paths.([]interface{}); ok {
			m.excludePaths = nil
			for _, p := range ps {
				if s, ok := p.(string); ok {
					m.excludePaths = append(m.excludePaths, s)
				}
			}
		}
	}

	return nil
}

// Scan walks the filesystem to find all current SUID/SGID binaries and compares
// them against the baseline.
//
// On first run (baseline not initialized), it silently records the current state
// and returns no findings. This is by design — we cannot distinguish legitimate
// from malicious SUID files on a system we have never seen before. The operator
// should verify the system is clean before first deployment.
//
// On subsequent runs, it reports:
//   - New SUID/SGID files not in baseline (likely compromise or unplanned install)
//   - Removed SUID/SGID files (anti-forensics, broken updates, or legitimate removal)
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current := m.findSuidBinaries(ctx)

	if !m.baseline.Initialized {
		// First run: trust the current state as the baseline. This is the only
		// sane default since we cannot know whether existing SUID files are
		// legitimate without external context.
		m.baseline = SuidBaseline{Initialized: true, Entries: current}
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding

	// Detect newly-appeared SUID/SGID binaries by checking for paths in the
	// current scan that do not exist in the baseline.
	for path, entry := range current {
		if _, ok := m.baseline.Entries[path]; !ok {
			sev := finding.SeverityHigh
			// SUID binaries in world-writable temp directories are almost
			// certainly malicious — no legitimate package installs SUID
			// binaries in /tmp. Escalate to critical severity.
			if filepath.HasPrefix(path, "/tmp") || filepath.HasPrefix(path, "/var/tmp") {
				sev = finding.SeverityCritical
			}
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "suid-unexpected:" + path,
				Severity:  sev,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("unexpected SUID/SGID binary: %s", path),
				Detail: map[string]interface{}{
					"path": path,
					"mode": fmt.Sprintf("%04o", entry.Mode),
				},
			})
		}
	}

	// Detect removed SUID/SGID binaries. While less alarming than new ones,
	// removal can indicate anti-forensics cleanup, broken package updates,
	// or intentional hardening that should be rebaselined.
	for path := range m.baseline.Entries {
		if _, ok := current[path]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "suid-removed:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("SUID/SGID binary removed: %s", path),
				Detail:    map[string]interface{}{"path": path},
			})
		}
	}

	return findings, nil
}

// Rebaseline replaces the stored baseline with the current filesystem state.
// Call after verified system changes (package updates, intentional hardening)
// to suppress expected findings on subsequent scans.
func (m *Module) Rebaseline(ctx context.Context) error {
	m.baseline = SuidBaseline{Initialized: true, Entries: m.findSuidBinaries(ctx)}
	return m.store.Save(m.Name(), m.baseline)
}

// findSuidBinaries walks all configured scan paths and returns a map of every
// file that has the SUID or SGID bit set. The map is keyed by absolute path
// for O(1) lookup during baseline comparison.
//
// The walk is context-aware: it checks for cancellation on every file visit
// so that long-running scans can be interrupted promptly by scan timeouts.
// Filesystem errors (permission denied, broken symlinks) are silently skipped
// rather than aborting the entire walk, because partial results are more
// useful than no results.
func (m *Module) findSuidBinaries(ctx context.Context) map[string]SuidEntry {
	result := make(map[string]SuidEntry)

	for _, root := range m.scanPaths {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			// Check for context cancellation on every file to allow prompt
			// abort when the scan timeout is reached.
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err != nil {
				// Silently skip files/dirs we cannot stat (permission denied,
				// broken symlinks, etc.). Partial results are better than
				// aborting the entire scan.
				return nil
			}

			// Skip excluded paths entirely. For directories, use SkipDir to
			// avoid descending into potentially huge subtrees (e.g., Docker
			// overlay storage can contain millions of files).
			for _, excl := range m.excludePaths {
				if filepath.HasPrefix(path, excl) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}

			// Skip directories themselves — we only care about files
			if info.IsDir() {
				return nil
			}

			// Check for SUID (execute-as-owner) or SGID (execute-as-group) bits.
			// Both are privilege escalation vectors: SUID gives the caller the
			// file owner's privileges, SGID gives the file group's privileges.
			mode := info.Mode()
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				result[path] = SuidEntry{Path: path, Mode: mode}
			}

			return nil
		})
	}

	return result
}
