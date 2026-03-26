// Package fileintegrity implements a file integrity monitoring (FIM) scanner for Trapline.
//
// # What It Monitors and Why
//
// This module tracks SHA-256 hashes, permissions (mode bits), ownership (UID/GID),
// and modification times of security-critical system files. File integrity monitoring
// is one of the most fundamental security controls because nearly every post-exploitation
// activity -- persistence, privilege escalation, defense evasion -- requires modifying
// files on disk.
//
// # How It Works
//
// The module operates in two complementary modes:
//
//   - Polling mode (primary): On each Scan() call, the module expands glob patterns in
//     the watch list, stats each file, and computes SHA-256 hashes. An mtime-based
//     optimization skips the expensive hash computation when a file's mtime, mode, and
//     ownership are unchanged since the last baseline, cutting scan time by ~95% on
//     stable systems.
//
//   - Inotify mode (supplementary): An fsnotify watcher monitors all watched files in
//     real time between polling intervals. Inotify events trigger immediate file scans
//     and queue findings for the next Scan() call. This provides near-real-time
//     detection (sub-second) rather than waiting for the next poll cycle.
//
// On first run, the module enters "learning mode" -- it records the current state as
// baseline and produces no findings. Subsequent scans compare against this baseline.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - Persistence (T1098): Modified /etc/ssh/sshd_config or authorized_keys to allow
//     attacker SSH access.
//   - Persistence (T1136): New entries in /etc/passwd or /etc/shadow indicating
//     backdoor account creation.
//   - Privilege Escalation (T1548): Modified /etc/sudoers granting elevated privileges.
//   - Credential Access (T1003): Modified /etc/shadow indicating password hash tampering.
//   - Defense Evasion (T1070): Replaced or modified system binaries to hide attacker
//     activity.
//   - Permission changes on sensitive files (e.g., world-readable /etc/shadow).
//   - File removal (e.g., deleted audit logs or security configurations).
//   - New files appearing in monitored paths (e.g., a new sudoers.d drop-in).
//
// # What It Does NOT Catch (Known Limitations)
//
//   - Files outside the watch list: only explicitly listed paths/globs are monitored.
//     An attacker placing a backdoor in an unmonitored directory will not be detected.
//   - In-memory-only attacks: modifications to running processes that never touch disk.
//   - Rootkits that intercept read() syscalls: the hash will match what the kernel
//     returns, which may be the original clean file content.
//   - Files larger than 100 MB are tracked by metadata only (no hash), so content
//     changes that preserve mtime/mode/ownership will be missed.
//   - Symlink targets: symlinks are tracked but not followed for hashing, so changes
//     to the target file are only caught if the target itself is in the watch list.
//   - Race conditions: a file could be modified and restored between polls (though
//     inotify mode significantly reduces this window).
//
// # False Positive Risks
//
//   - Legitimate package manager updates will modify system files. Rebaseline after
//     planned maintenance windows.
//   - Configuration management tools (Ansible, Chef, Puppet) making authorized changes.
//   - Log rotation or automated processes that touch monitored files.
//   - Mitigation: use the Rebaseline() method after authorized changes, or configure
//     the alert pipeline to suppress known-good change patterns.
//
// # Performance Characteristics
//
//   - I/O: One stat() call per watched file per scan. One open()+read() (SHA-256) only
//     for files whose mtime changed. Inotify adds kernel-level watches (no polling I/O).
//   - CPU: SHA-256 hashing is the main cost, but the mtime optimization means only
//     changed files are hashed.
//   - Memory: Baseline map is proportional to the number of watched files (typically
//     tens to low hundreds). Pending inotify findings are capped at 100 to prevent
//     unbounded growth.
//   - Inotify watches: One watch per file (not directory), bounded by the watch list
//     size and the kernel's fs.inotify.max_user_watches limit.
//
// # Configuration Options
//
//   - watch_extra ([]string): Additional file paths or glob patterns to monitor beyond
//     the built-in default list. Set in the module's Settings map.
//   - The default watch list covers: /etc/ssh/sshd_config, /etc/passwd, /etc/shadow,
//     /etc/group, /etc/gshadow, /etc/sudoers, /etc/crontab, /etc/docker/daemon.json.
package fileintegrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// FileEntry captures the security-relevant attributes of a single monitored file.
// The Hash field is the SHA-256 hex digest of file contents (empty for symlinks
// and files exceeding maxHashSize). Mode, Owner, and Group detect permission
// changes independently of content changes. MTime enables the fast-path
// optimization that skips hashing when metadata is unchanged.
type FileEntry struct {
	Hash  string      `json:"hash"`
	Mode  os.FileMode `json:"mode"`
	Owner uint32      `json:"owner"`
	Group uint32      `json:"group"`
	MTime time.Time   `json:"mtime"`
}

// Module is the file integrity scanner. It maintains a baseline of file states
// and detects deviations on each scan. The module supports both periodic polling
// and real-time inotify-based detection for minimal latency on critical changes.
type Module struct {
	store          *baseline.Store
	baseline       map[string]FileEntry
	baselineLoaded bool
	watchList      []string

	// Real-time inotify watcher (supplementary to polling).
	// When inotify is available, changes between poll intervals are detected
	// within milliseconds and queued as pendingFindings.
	watcher        *fsnotify.Watcher
	pendingMu      sync.Mutex
	pendingFindings []finding.Finding
	cancelWatch    context.CancelFunc
}

// New creates an uninitialized Module. Call Init() before use.
func New() *Module {
	return &Module{}
}

// Name returns the module identifier used for baseline storage and finding IDs.
func (m *Module) Name() string { return "file-integrity" }

// Init sets up the baseline store, configures the watch list, loads any
// persisted baseline from disk, and starts the inotify watcher. The watch list
// is intentionally conservative by default -- it targets the files most commonly
// modified during post-exploitation rather than attempting to watch the entire
// filesystem (which would be prohibitively expensive and noisy).
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store

	// Default watch list: these are the files most commonly targeted in
	// post-exploitation for persistence, privilege escalation, and credential
	// theft. Each one maps to specific MITRE ATT&CK techniques.
	m.watchList = []string{
		"/etc/ssh/sshd_config",    // T1098 - SSH configuration tampering
		"/etc/passwd",             // T1136 - backdoor account creation
		"/etc/shadow",             // T1003 - password hash theft/tampering
		"/etc/group",              // T1098 - group membership manipulation
		"/etc/gshadow",            // T1098 - group password changes
		"/etc/sudoers",            // T1548 - privilege escalation via sudo
		"/etc/crontab",            // T1053 - persistence via scheduled tasks
		"/etc/docker/daemon.json", // Container escape / config tampering
	}

	// Add extra watch paths from config. This allows operators to extend
	// monitoring to application-specific files (e.g., nginx.conf, .htaccess)
	// without modifying the source code.
	if extra, ok := cfg.Settings["watch_extra"]; ok {
		if paths, ok := extra.([]interface{}); ok {
			for _, p := range paths {
				if s, ok := p.(string); ok {
					m.watchList = append(m.watchList, s)
				}
			}
		}
	}

	// Load existing baseline from the persistent store. If no baseline exists
	// yet, the first Scan() call will enter learning mode and establish one.
	m.baseline = make(map[string]FileEntry)
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)

	// Start real-time inotify watcher (best-effort; falls back to polling-only).
	// This is defense-in-depth: polling catches everything eventually, but
	// inotify catches changes in near-real-time between poll intervals.
	m.startWatcher()

	return nil
}

// startWatcher creates an fsnotify watcher and begins monitoring all files in
// the expanded watchList. If inotify is unavailable or watch limits are hit,
// it silently falls back to polling-only mode. This is intentionally best-effort:
// inotify provides faster detection but polling is the reliable fallback.
func (m *Module) startWatcher() {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		// inotify unavailable (e.g., running in a container without /dev/inotify,
		// or kernel compiled without CONFIG_INOTIFY_USER). Fall back to polling.
		return
	}

	// Expand globs and add individual file watches. We watch files directly
	// rather than directories to avoid noisy events from unrelated files.
	watchCount := 0
	for _, pattern := range m.watchList {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if matches == nil {
			// No glob expansion occurred (literal path). Try to watch it anyway
			// in case the file is created later (inotify will fail, but that is ok).
			matches = []string{pattern}
		}
		for _, path := range matches {
			if err := w.Add(path); err != nil {
				// Could not watch this file. Common reasons: file does not exist yet,
				// fs.inotify.max_user_watches limit reached, or permission denied.
				continue
			}
			watchCount++
		}
	}

	if watchCount == 0 {
		w.Close()
		return
	}

	m.watcher = w

	ctx, cancel := context.WithCancel(context.Background())
	m.cancelWatch = cancel

	go m.watchLoop(ctx, w)
}

// watchLoop processes fsnotify events and generates findings for changed files.
// The watcher is passed directly (rather than reading m.watcher) to avoid races
// with the Close() method setting m.watcher to nil from another goroutine.
func (m *Module) watchLoop(ctx context.Context, w *fsnotify.Watcher) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.Events:
			if !ok {
				return
			}
			// Filter to security-relevant events only. We care about:
			// - Write: file content changed (most common modification)
			// - Create: new file appeared (editor save-and-replace pattern)
			// - Remove: file deleted (evidence tampering, config removal)
			// - Chmod: permission/ownership changed (privilege escalation)
			// Rename events are intentionally excluded as they generate a
			// Remove+Create pair anyway.
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Chmod) == 0 {
				continue
			}

			path := event.Name

			// Re-add the watch after Remove or Create events. Many text editors
			// (vim, nano, sed -i) save files by writing to a temp file and
			// renaming, which removes the inotify watch on the original path.
			// Re-adding ensures we continue to monitor the file at this path.
			if event.Op&(fsnotify.Remove|fsnotify.Create) != 0 {
				_ = w.Add(path) // ignore errors -- file may be genuinely gone
			}

			// Only generate findings if we have a baseline
			m.pendingMu.Lock()
			if !m.baselineLoaded {
				m.pendingMu.Unlock()
				continue
			}
			m.pendingMu.Unlock()

			findings := m.scanSingleFile(path)
			if len(findings) > 0 {
				m.pendingMu.Lock()
				// Cap pending findings to avoid unbounded memory growth
				if len(m.pendingFindings) < 100 {
					m.pendingFindings = append(m.pendingFindings, findings...)
				}
				m.pendingMu.Unlock()
			}

		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Printf("fileintegrity: watcher error: %v", err)
		}
	}
}

// scanSingleFile scans one file against the baseline and returns any findings.
// This is the inotify-triggered path (as opposed to the polling path in Scan()).
// Findings generated here include "source":"inotify" in their detail to
// distinguish them from polling-detected changes for forensic analysis.
func (m *Module) scanSingleFile(path string) []finding.Finding {
	var findings []finding.Finding

	m.pendingMu.Lock()
	base, hasBaseline := m.baseline[path]
	m.pendingMu.Unlock()

	entry, err := scanFile(path)
	if err != nil {
		// File may have been removed
		if hasBaseline {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "file-removed:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("monitored file removed: %s", path),
				Detail:    map[string]interface{}{"path": path, "source": "inotify"},
			})
		}
		return findings
	}

	if !hasBaseline {
		// New file detected via inotify
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "file-added:" + path,
			Severity:  finding.SeverityMedium,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("new file detected: %s", path),
			Detail: map[string]interface{}{
				"path":   path,
				"hash":   entry.Hash,
				"mode":   fmt.Sprintf("%04o", entry.Mode),
				"source": "inotify",
			},
		})
		return findings
	}

	if entry.Hash != base.Hash {
		sev := finding.SeverityMedium
		if isSensitivePath(path) {
			sev = finding.SeverityHigh
		}
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "file-modified:" + path,
			Severity:  sev,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("%s modified outside of package manager", filepath.Base(path)),
			Detail: map[string]interface{}{
				"path":          path,
				"baseline_hash": base.Hash,
				"current_hash":  entry.Hash,
				"mode":          fmt.Sprintf("%04o", entry.Mode),
				"mtime":         entry.MTime.Format(time.RFC3339),
				"source":        "inotify",
			},
		})
	}

	if entry.Mode != base.Mode || entry.Owner != base.Owner || entry.Group != base.Group {
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "file-permission-changed:" + path,
			Severity:  finding.SeverityMedium,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("%s permissions changed", filepath.Base(path)),
			Detail: map[string]interface{}{
				"path":           path,
				"baseline_mode":  fmt.Sprintf("%04o", base.Mode),
				"current_mode":   fmt.Sprintf("%04o", entry.Mode),
				"baseline_owner": base.Owner,
				"current_owner":  entry.Owner,
				"source":         "inotify",
			},
		})
	}

	return findings
}

// Close shuts down the inotify watcher. Safe to call even if the watcher was
// never started (polling-only mode).
func (m *Module) Close() {
	if m.cancelWatch != nil {
		m.cancelWatch()
	}
	if m.watcher != nil {
		m.watcher.Close()
	}
}

// Scan performs a full poll-based scan of all watched files and merges in any
// pending findings from the inotify watcher. This two-phase approach ensures
// that nothing is missed: inotify catches changes between polls (fast), and
// polling catches anything inotify might have dropped (reliable).
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current := make(map[string]FileEntry)
	var findings []finding.Finding

	// Drain any findings from the real-time inotify watcher
	m.pendingMu.Lock()
	if len(m.pendingFindings) > 0 {
		findings = append(findings, m.pendingFindings...)
		m.pendingFindings = nil
	}
	m.pendingMu.Unlock()

	// Expand globs and scan files.
	// Optimization: if a file's mtime hasn't changed since baseline,
	// skip the expensive SHA-256 hash and reuse the baseline entry.
	// This cuts scan time by 95%+ on stable systems.
	for _, pattern := range m.watchList {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if matches == nil {
			matches = []string{pattern}
		}
		for _, path := range matches {
			if base, ok := m.baseline[path]; ok && m.baselineLoaded {
				// Fast path: check mtime + mode + ownership without hashing
				info, err := os.Lstat(path)
				if err != nil {
					continue
				}
				var owner, group uint32
				if stat, ok := info.Sys().(*syscall.Stat_t); ok {
					owner = stat.Uid
					group = stat.Gid
				}
				if info.ModTime().Equal(base.MTime) && info.Mode() == base.Mode && owner == base.Owner && group == base.Group {
					// Nothing changed — reuse baseline entry, skip hash
					current[path] = base
					continue
				}
			}
			// Slow path: file is new, modified, or permissions changed — full scan
			entry, err := scanFile(path)
			if err != nil {
				continue
			}
			current[path] = entry
		}
	}

	// No baseline yet = learning mode
	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	// Check for modified and permission-changed files
	for path, cur := range current {
		if base, ok := m.baseline[path]; ok {
			if cur.Hash != base.Hash {
				sev := finding.SeverityMedium
				if isSensitivePath(path) {
					sev = finding.SeverityHigh
				}
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "file-modified:" + path,
					Severity:  sev,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("%s modified outside of package manager", filepath.Base(path)),
					Detail: map[string]interface{}{
						"path":          path,
						"baseline_hash": base.Hash,
						"current_hash":  cur.Hash,
						"mode":          fmt.Sprintf("%04o", cur.Mode),
						"mtime":         cur.MTime.Format(time.RFC3339),
					},
				})
			}
			if cur.Mode != base.Mode || cur.Owner != base.Owner || cur.Group != base.Group {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "file-permission-changed:" + path,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("%s permissions changed", filepath.Base(path)),
					Detail: map[string]interface{}{
						"path":           path,
						"baseline_mode":  fmt.Sprintf("%04o", base.Mode),
						"current_mode":   fmt.Sprintf("%04o", cur.Mode),
						"baseline_owner": base.Owner,
						"current_owner":  cur.Owner,
					},
				})
			}
		} else {
			// New file
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "file-added:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new file detected: %s", path),
				Detail: map[string]interface{}{
					"path": path,
					"hash": cur.Hash,
					"mode": fmt.Sprintf("%04o", cur.Mode),
				},
			})
		}
	}

	// Check for removed files
	for path := range m.baseline {
		if _, ok := current[path]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "file-removed:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("monitored file removed: %s", path),
				Detail:    map[string]interface{}{"path": path},
			})
		}
	}

	return findings, nil
}

// Rebaseline performs a full scan (no mtime optimization) and saves the result
// as the new baseline. Unlike Scan(), this always hashes every file to ensure
// the baseline is complete and accurate. Call this after planned system changes
// (package updates, config management runs) to prevent false positives.
func (m *Module) Rebaseline(ctx context.Context) error {
	current := make(map[string]FileEntry)
	for _, pattern := range m.watchList {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if matches == nil {
			matches = []string{pattern}
		}
		for _, path := range matches {
			entry, err := scanFile(path)
			if err != nil {
				continue
			}
			current[path] = entry
		}
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

// maxHashSize is the maximum file size (100MB) we will hash; larger files
// get metadata-only tracking to avoid expensive I/O.
const maxHashSize = 100 * 1024 * 1024

// scanFile collects the full security-relevant metadata and SHA-256 hash of a
// single file. Uses Lstat (not Stat) to avoid following symlinks -- we want to
// detect changes to the link itself, not the target. The target should be
// monitored separately if it matters.
func scanFile(path string) (FileEntry, error) {
	// Lstat is used intentionally instead of Stat to avoid following symlinks.
	// Following symlinks would let an attacker redirect a monitored path to a
	// clean file while the real target is modified.
	info, err := os.Lstat(path)
	if err != nil {
		return FileEntry{}, err
	}

	// Extract UID/GID from the platform-specific stat structure.
	// The type assertion to *syscall.Stat_t is Linux-specific but this
	// tool only targets Linux servers.
	var owner, group uint32
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		owner = stat.Uid
		group = stat.Gid
	}

	// Symlinks: track metadata only (mode, mtime, ownership). Hashing the
	// link target content would be misleading because changing the link itself
	// would not change the hash (the target content might be identical).
	if info.Mode()&os.ModeSymlink != 0 {
		return FileEntry{
			Mode:  info.Mode(),
			MTime: info.ModTime(),
			Owner: owner,
			Group: group,
		}, nil
	}

	// Skip hashing for files larger than 100MB; record metadata only
	if info.Size() > maxHashSize {
		return FileEntry{
			Mode:  info.Mode(),
			Owner: owner,
			Group: group,
			MTime: info.ModTime(),
		}, nil
	}

	// Open for reading to compute SHA-256. If open fails (e.g., permission
	// denied), return metadata-only entry rather than failing the entire scan.
	// This graceful degradation ensures we still detect permission/ownership
	// changes even on files we cannot read.
	f, err := os.Open(path)
	if err != nil {
		return FileEntry{
			Mode:  info.Mode(),
			MTime: info.ModTime(),
			Owner: owner,
			Group: group,
		}, nil
	}
	defer f.Close()

	// Compute SHA-256 hash by streaming file content through the hasher.
	// This avoids loading the entire file into memory.
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileEntry{}, err
	}

	return FileEntry{
		Hash:  hex.EncodeToString(h.Sum(nil)),
		Mode:  info.Mode(),
		Owner: owner,
		Group: group,
		MTime: info.ModTime(),
	}, nil
}

// isSensitivePath returns true for files that warrant High severity when modified.
// These are the crown jewels of a Linux system: authentication databases, SSH
// configuration, and privilege escalation configuration. Modifications to these
// files are more likely to indicate active compromise than changes to other
// monitored files.
func isSensitivePath(path string) bool {
	sensitive := []string{
		"/etc/shadow",          // password hashes -- modification means credential tampering
		"/etc/gshadow",         // group password hashes
		"/etc/sudoers",         // sudo rules -- modification grants root access
		"/etc/ssh/sshd_config", // SSH config -- can enable root login, weaken auth
		"/etc/passwd",          // user database -- new entries mean backdoor accounts
	}
	for _, s := range sensitive {
		if path == s {
			return true
		}
	}
	return false
}
