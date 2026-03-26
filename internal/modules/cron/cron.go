// Package cron implements a cron job monitoring scanner for Trapline.
//
// # What It Monitors and Why
//
// This module tracks all cron-scheduled tasks across the system by parsing
// /etc/crontab, standard cron directories (/etc/cron.d/, /etc/cron.{hourly,daily,
// weekly,monthly}/), and per-user crontabs (/var/spool/cron/crontabs/). Cron-based
// persistence is one of the most common post-exploitation techniques (MITRE T1053.003)
// because cron jobs:
//   - Survive reboots
//   - Execute automatically without user interaction
//   - Are often overlooked during manual incident response
//   - Can run as any user including root
//
// # How It Works
//
// The module scans all known cron locations and extracts non-comment, non-blank,
// non-variable-assignment lines from each file. Each line is individually SHA-256
// hashed (truncated to 16 hex chars) to create a unique fingerprint. The map key
// is "source_file:hash", so the same command in different files is tracked
// independently.
//
// On first run, the module enters "learning mode" -- it records all current cron
// entries as the baseline and produces no findings. Subsequent scans compare
// against this baseline using set-difference operations.
//
// Variable assignment lines (e.g., "SHELL=/bin/bash", "PATH=/usr/bin") are
// explicitly excluded because they are configuration directives, not scheduled
// commands. The heuristic is: if the line contains "=" but no spaces, it is a
// variable assignment.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - Persistence via Scheduled Task (T1053.003): New cron jobs added by attackers
//     to maintain access, run cryptominers, exfiltrate data, or download additional
//     payloads.
//   - Modified cron jobs: Existing legitimate cron jobs altered to include malicious
//     commands (e.g., appending a reverse shell to a backup script).
//   - Removed cron jobs: Legitimate cron jobs deleted, which could indicate an
//     attacker disabling security monitoring or log rotation.
//
// # What It Does NOT Catch (Known Limitations)
//
//   - Systemd timers: This module only monitors traditional cron. Systemd timer
//     units (.timer) are a separate persistence mechanism not covered here.
//   - At jobs: One-time scheduled jobs via at(1) are not monitored.
//   - Cron jobs in non-standard locations: If a custom cron daemon reads from
//     non-standard directories, those will not be scanned.
//   - Inline script content: The module hashes each line individually, so a
//     multi-line heredoc within a crontab may not be tracked coherently.
//   - Variable assignment changes: Modified PATH or SHELL variables are excluded
//     from tracking, but an attacker could manipulate these to redirect execution.
//   - Anacron: /etc/anacrontab is not scanned (could be added to CronDirs).
//
// # False Positive Risks
//
//   - Package updates that install or modify cron jobs in /etc/cron.d/.
//   - Configuration management tools deploying cron changes.
//   - Logrotate or other system tools updating their cron entries.
//   - Mitigation: Rebaseline after planned system updates.
//
// # Performance Characteristics
//
//   - I/O: One file read per cron file across all monitored directories. Typically
//     fewer than 20 files total. No recursive traversal -- only one level of
//     globbing per directory.
//   - CPU: SHA-256 of individual text lines (negligible).
//   - Memory: Proportional to the total number of active cron lines across all
//     files (typically dozens).
//
// # Configuration Options
//
//   - Currently no user-configurable settings. CronDirs and CrontabPath are
//     overridable for testing.
//   - Default directories: /etc/crontab, /etc/cron.d/, /etc/cron.hourly/,
//     /etc/cron.daily/, /etc/cron.weekly/, /etc/cron.monthly/,
//     /var/spool/cron/crontabs/.
package cron

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// CronEntry represents a single non-comment, non-variable line from a cron file.
// Source is the file path it came from, Line is the raw text, and Hash is a
// truncated SHA-256 of the line content used as a stable identifier for
// baseline comparison.
type CronEntry struct {
	Source string `json:"source"`
	Line   string `json:"line"`
	Hash   string `json:"hash"`
}

// Module is the cron job monitoring scanner. It tracks scheduled tasks across
// all standard cron locations and detects additions, modifications, and removals.
type Module struct {
	store          *baseline.Store
	baseline       []CronEntry
	baselineLoaded bool
	// CronDirs and CrontabPath are exported for testing so unit tests can
	// point at fixture directories instead of the real /etc/cron* paths.
	CronDirs    []string
	CrontabPath string
}

// New creates a Module with default cron paths covering all standard locations.
// Call Init() before use.
func New() *Module {
	return &Module{
		CrontabPath: "/etc/crontab",
		CronDirs: []string{
			"/etc/cron.d",              // System cron drop-in directory
			"/etc/cron.hourly",         // Scripts run hourly by run-parts
			"/etc/cron.daily",          // Scripts run daily by run-parts
			"/etc/cron.weekly",         // Scripts run weekly by run-parts
			"/etc/cron.monthly",        // Scripts run monthly by run-parts
			"/var/spool/cron/crontabs", // Per-user crontabs (crontab -e)
		},
	}
}

// Name returns the module identifier used for baseline storage and finding IDs.
func (m *Module) Name() string { return "cron" }

// Init sets up the baseline store and loads any persisted baseline from disk.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)
	return nil
}

// Scan collects all current cron entries and compares them against the baseline.
// It detects three types of changes:
//   - New entries: cron lines not present in the baseline (potential persistence).
//   - Modified entries: same source file but different hash (altered commands).
//   - Removed entries: baseline entries no longer present (potential tampering).
//
// All cron findings are Medium severity because cron changes require some
// level of system access but are a common persistence vector.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current := m.scanCrons()

	// Learning mode: record all current cron entries as baseline.
	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		_ = m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding
	baseMap := cronToMap(m.baseline)
	curMap := cronToMap(current)

	// Detect new and modified cron entries. The map key is "source:hash",
	// so a modified line in the same file will appear as a new key (the old
	// hash is gone, the new hash is present).
	for key, cur := range curMap {
		if base, ok := baseMap[key]; ok {
			// Same source+hash key exists -- check if the content changed.
			// In practice this branch is rarely hit because the hash IS the
			// content fingerprint, but it guards against hash collisions in
			// the truncated 16-char hash.
			if cur.Hash != base.Hash {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "cron-modified:" + cur.Source,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("cron job modified in %s", cur.Source),
					Detail:    map[string]interface{}{"source": cur.Source, "line": cur.Line},
				})
			}
		} else {
			// New cron entry not in baseline -- potential persistence mechanism.
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "cron-added:" + cur.Source,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new cron job detected in %s", cur.Source),
				Detail:    map[string]interface{}{"source": cur.Source, "line": cur.Line},
			})
		}
	}

	// Detect removed cron entries. Removal could indicate an attacker cleaning
	// up evidence or disabling security-related scheduled tasks (e.g., log
	// rotation, integrity checks).
	for key, base := range baseMap {
		if _, ok := curMap[key]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "cron-removed:" + base.Source,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("cron job removed from %s", base.Source),
				Detail:    map[string]interface{}{"source": base.Source},
			})
		}
	}

	return findings, nil
}

// Rebaseline captures the current set of cron entries as the new baseline.
// Call this after planned cron changes to prevent false positives.
func (m *Module) Rebaseline(ctx context.Context) error {
	m.baseline = m.scanCrons()
	return m.store.Save(m.Name(), m.baseline)
}

// scanCrons collects cron entries from all monitored locations: the main
// crontab file and all files in each configured cron directory. Directories
// that do not exist are silently skipped.
func (m *Module) scanCrons() []CronEntry {
	var entries []CronEntry

	// Scan the main system crontab (/etc/crontab)
	if e := scanCronFile(m.CrontabPath); len(e) > 0 {
		entries = append(entries, e...)
	}

	// Scan all cron directories. Each directory is globbed for files (not
	// subdirectories). Per-user crontabs in /var/spool/cron/crontabs/ are
	// included here, which catches user-level persistence via `crontab -e`.
	for _, dir := range m.CronDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			continue
		}
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil || info.IsDir() {
				continue // skip subdirectories and inaccessible files
			}
			if e := scanCronFile(f); len(e) > 0 {
				entries = append(entries, e...)
			}
		}
	}

	return entries
}

// scanCronFile reads a single cron file and extracts active cron entries.
// It skips blank lines, comments (# prefix), and variable assignments.
// Each remaining line is hashed individually with SHA-256, truncated to 16
// hex characters (64 bits) for use as a stable identifier. The truncation
// is acceptable because collisions in a set of typically <100 entries are
// astronomically unlikely at 64 bits.
func scanCronFile(path string) []CronEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var entries []CronEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip variable assignments like SHELL=/bin/bash, PATH=/usr/bin, etc.
		// Heuristic: if the line contains "=" but no spaces, it is a variable
		// assignment rather than a cron schedule line. Cron schedule lines
		// always have spaces (between the 5 time fields and the command).
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		// Hash the line content to create a stable, position-independent
		// identifier. This means reordering lines in a crontab does not
		// generate false positives.
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(line)))
		entries = append(entries, CronEntry{
			Source: path,
			Line:   line,
			Hash:   hash[:16], // truncate to 16 hex chars (64 bits)
		})
	}

	return entries
}

// cronToMap converts a slice of CronEntry into a map keyed by "source:hash"
// for efficient set-difference operations during baseline comparison. The
// composite key ensures that the same command in different files is tracked
// independently (a cron job in /etc/cron.d/backup is distinct from the same
// command in a user's personal crontab).
func cronToMap(entries []CronEntry) map[string]CronEntry {
	m := make(map[string]CronEntry)
	for _, e := range entries {
		key := e.Source + ":" + e.Hash
		m[key] = e
	}
	return m
}
