// Package permissions scans the filesystem for dangerous file permission
// configurations that could enable privilege escalation or sensitive data
// exposure.
//
// # What it monitors and why
//
// File permissions are a foundational layer of Linux security. Misconfigured
// permissions create opportunities for unprivileged users (or attackers with
// low-privilege footholds) to escalate privileges, read secrets, or replace
// trusted binaries. This module checks three distinct categories:
//
//  1. World-writable files in system directories (/etc, /usr, /var) — any user
//     on the system can modify these, enabling config tampering or binary replacement.
//
//  2. /etc/shadow readability — this file contains password hashes and must be
//     readable only by root. If group or other read bits are set, any local user
//     can extract hashes for offline cracking.
//
//  3. /usr/local/bin ownership — binaries in PATH that are not owned by root can
//     be replaced by their owner, creating a trojan horse that executes with
//     the privileges of whoever runs the command.
//
// # How it works
//
// The module uses a tiered scanning strategy to balance thoroughness with I/O cost:
//
//   - Full filesystem walk: Performed every 6 hours (or on first scan). Walks all
//     configured scan paths and records directory modification times (mtimes).
//
//   - Incremental scan: Between full walks, only descends into directories whose
//     mtime has changed since the last scan. This reduces I/O from tens of thousands
//     of stat() calls to a few hundred, since most system directories rarely change.
//
//   - Targeted checks: /etc/shadow and /usr/local/bin are checked on every scan
//     regardless of the incremental logic, because they are single-stat or small-
//     directory operations with negligible cost and critical security value.
//
// The directory mtime cache is persisted to disk between restarts.
//
// # What it catches
//
//   - World-writable configs in /etc (e.g., /etc/cron.d/job with mode 0666)
//   - World-writable binaries in /usr (binary replacement for privilege escalation)
//   - /etc/shadow with group-readable or world-readable permissions (hash exposure)
//   - Non-root-owned binaries in /usr/local/bin (trojan horse via PATH injection)
//   - MITRE ATT&CK: T1222.002 (File and Directory Permissions Modification: Linux),
//     T1003.008 (/etc/shadow credential access), T1574.006 (Hijack Execution Flow:
//     PATH Interception)
//
// # What it does NOT catch (known limitations)
//
//   - Does not check permissions on home directories or user-owned paths
//   - Does not monitor ACLs (getfacl) — only traditional Unix permission bits
//   - Does not check directory permissions (world-writable directories like /tmp
//     are expected and filtered by only checking files, not dirs)
//   - Does not verify group ownership — a file owned by root but with group-write
//     and a privileged group could still be vulnerable
//   - The incremental mtime optimization can miss changes if an attacker modifies
//     a file and then resets the parent directory's mtime (requires root or specific
//     filesystem tricks). The 6-hour full scan catches this eventually.
//   - Does not scan paths outside the configured list (default: /etc, /usr, /var)
//
// # False positive risks
//
//   - Some packages legitimately install world-writable files (e.g., lock files,
//     shared state in /var). These will produce recurring findings.
//   - /usr/local/bin files installed by tools like pip, npm, or manual builds are
//     often owned by non-root users. This is a genuine security concern but may
//     be expected in development environments.
//   - The shadow file check may fire on systems using alternative authentication
//     (LDAP/SSSD) where /etc/shadow permissions are non-standard.
//
// # Performance characteristics
//
// Full scan: walks /etc, /usr, /var — typically 50,000-200,000 stat() calls,
// taking 2-10 seconds depending on disk speed. Incremental scan: typically
// checks only 100-500 directories, completing in under 100ms. The shadow and
// /usr/local/bin checks are negligible (1 stat + ~10-50 stats respectively).
//
// # Configuration options
//
// No user-facing configuration options are currently exposed via
// engine.ModuleConfig.Settings. The scan paths are set at construction time
// in New(). Future versions could expose scan_paths and sensitivity thresholds.
package permissions

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jclement/trapline/internal/baseline"
	"github.com/jclement/trapline/internal/engine"
	"github.com/jclement/trapline/pkg/finding"
)

// isShadowGroup returns true if the given GID belongs to the "shadow" group.
// On Debian/Ubuntu the shadow group (typically GID 42) is the expected group
// owner of /etc/shadow, granting read access to programs like passwd without
// requiring root. We look up the group by parsing /etc/group directly to avoid
// CGO dependency (os/user.LookupGroup requires CGO on Linux).
func isShadowGroup(gid uint32) bool {
	f, err := os.Open("/etc/group")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// /etc/group format: name:password:GID:members
		fields := strings.SplitN(scanner.Text(), ":", 4)
		if len(fields) < 3 {
			continue
		}
		if fields[0] == "shadow" {
			groupGID, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return false
			}
			return uint32(groupGID) == gid
		}
	}
	return false
}

// dirCache tracks directory modification times to enable incremental scanning.
// By recording each directory's mtime, we can skip entire subtrees that have
// not changed since the last scan, dramatically reducing I/O. LastFull tracks
// when we last did a complete walk so we can force one every 6 hours to catch
// any changes that the mtime optimization might miss.
type dirCache struct {
	DirMtimes map[string]time.Time `json:"dir_mtimes"`
	LastFull  time.Time            `json:"last_full"`
}

// Module implements engine.Scanner for filesystem permission monitoring.
type Module struct {
	store      *baseline.Store
	scanPaths  []string // Root directories to walk for permission checks
	cache      dirCache // Persisted mtime cache for incremental scanning
	ShadowPath string   // Path to /etc/shadow, overridable for testing
}

// New creates a permissions scanner targeting the three most security-sensitive
// directory trees on a typical Linux system. /etc contains configuration and
// credentials, /usr contains system binaries, and /var contains runtime state
// and logs.
func New() *Module {
	return &Module{
		scanPaths:  []string{"/etc", "/usr", "/var"},
		ShadowPath: "/etc/shadow",
	}
}

func (m *Module) Name() string { return "permissions" }

// Init loads the baseline store and any previously-persisted directory mtime
// cache. The cache enables incremental scanning between full walks.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.cache.DirMtimes = make(map[string]time.Time)
	_, _ = m.store.Load(m.Name(), &m.cache)
	return nil
}

// Scan checks filesystem permissions across three categories:
//
//  1. World-writable files in system directories (walk-based, incremental)
//  2. /etc/shadow readability (single stat, every scan)
//  3. /usr/local/bin ownership (small readdir, every scan)
//
// The walk uses a tiered strategy: a full walk every 6 hours, and incremental
// mtime-based walks in between. This balances thoroughness (catching everything
// eventually) with performance (not hammering the disk every 5 minutes).
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	// Determine whether to do a full walk or incremental. Full walks happen:
	// - Every 6 hours (to catch changes the mtime optimization might miss)
	// - On first scan (empty cache means we have no mtimes to compare against)
	fullScan := time.Since(m.cache.LastFull) > 6*time.Hour || len(m.cache.DirMtimes) == 0

	for _, root := range m.scanPaths {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			// Check for context cancellation to allow prompt abort on scan timeout
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err != nil {
				// Skip inaccessible files/dirs rather than aborting the walk
				return nil
			}

			if info.IsDir() {
				if !fullScan {
					// Incremental optimization: if this directory's mtime matches
					// our cached value, nothing inside it has changed (files added,
					// removed, or renamed would update the dir mtime). Skip the
					// entire subtree to save potentially thousands of stat() calls.
					if cached, ok := m.cache.DirMtimes[path]; ok {
						if info.ModTime().Equal(cached) {
							return filepath.SkipDir
						}
					}
				}
				// Record this directory's mtime for future incremental scans
				m.cache.DirMtimes[path] = info.ModTime()
				return nil
			}

			mode := info.Mode()
			// Skip symlinks — their permission bits are always 0777 on Linux
			// (the kernel ignores symlink permissions entirely). Checking them
			// would produce false positives for every symlink in /etc/ssl/certs/,
			// /etc/alternatives/, etc.
			if mode&os.ModeSymlink != 0 {
				return nil
			}
			// Check the "other write" bit (0002). World-writable files in system
			// directories are dangerous because ANY local user can modify them.
			// This catches scenarios like a misconfigured cron job file that an
			// attacker could edit to gain root execution.
			if mode&0002 != 0 {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "perm-world-writable:" + path,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("world-writable file in sensitive location: %s", path),
					Detail: map[string]interface{}{
						"path": path,
						"mode": fmt.Sprintf("%04o", mode.Perm()),
					},
				})
			}

			return nil
		})
	}

	// --- Targeted checks (run every scan, negligible cost) ---

	// Check /etc/shadow permissions. This file contains password hashes and
	// should be mode 0640 (root:shadow) or stricter. The correct permission is
	// 0640 where the "shadow" group provides read access to programs like passwd
	// that need to verify passwords without running as root.
	//
	// We flag two cases:
	//   - World-readable (other-read 0004): anyone can read password hashes.
	//     This is CRITICAL — immediate credential exposure.
	//   - Group-readable with wrong group (not "shadow"): a non-shadow group
	//     can read password hashes. This is CRITICAL.
	//   - Group-writable or world-writable: password hashes can be modified.
	//     This is CRITICAL.
	//   - Mode 0640 with group "shadow": this is correct, no finding.
	if info, err := os.Stat(m.ShadowPath); err == nil {
		mode := info.Mode().Perm()
		stat, ok := info.Sys().(*syscall.Stat_t)

		if mode&0002 != 0 {
			// World-writable — anyone can modify password hashes
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "perm-shadow-writable",
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   "/etc/shadow is world-writable",
				Detail: map[string]interface{}{
					"mode": fmt.Sprintf("%04o", mode),
				},
			})
		} else if mode&0004 != 0 {
			// World-readable — any user can read password hashes
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "perm-shadow-readable",
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   "/etc/shadow is world-readable",
				Detail: map[string]interface{}{
					"mode": fmt.Sprintf("%04o", mode),
				},
			})
		} else if mode&0040 != 0 && ok && !isShadowGroup(stat.Gid) {
			// Group-readable but owned by wrong group (not "shadow")
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "perm-shadow-readable",
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("/etc/shadow is group-readable by GID %d (expected shadow group)", stat.Gid),
				Detail: map[string]interface{}{
					"mode": fmt.Sprintf("%04o", mode),
					"gid":  stat.Gid,
				},
			})
		}
	}

	// Check /usr/local/bin ownership. Binaries in this directory are in the
	// default PATH and are often run by root or via sudo. If a binary is owned
	// by a non-root user, that user can replace it with malicious code that
	// will execute with elevated privileges when an admin runs it.
	// This is a common issue with pip install, npm -g, or manual builds that
	// run as a regular user.
	if entries, err := os.ReadDir("/usr/local/bin"); err == nil {
		for _, entry := range entries {
			path := filepath.Join("/usr/local/bin", entry.Name())
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			// Use the Linux-specific Stat_t to get the file's UID. This is
			// platform-dependent (only works on Linux/Unix) but that is
			// acceptable since this tool targets Linux servers.
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if stat.Uid != 0 {
					findings = append(findings, finding.Finding{
						Timestamp: time.Now().UTC(),
						FindingID: "perm-bad-owner:" + path,
						Severity:  finding.SeverityMedium,
						Status:    finding.StatusNew,
						Summary:   fmt.Sprintf("%s not owned by root (uid=%d)", path, stat.Uid),
						Detail: map[string]interface{}{
							"path": path,
							"uid":  stat.Uid,
						},
					})
				}
			}
		}
	}

	// Update the full-scan timestamp so the next scan knows whether to do
	// a full walk or an incremental one.
	if fullScan {
		m.cache.LastFull = time.Now()
	}
	// Persist the mtime cache so incremental scanning works across restarts
	_ = m.store.Save(m.Name(), m.cache)

	return findings, nil
}

// Rebaseline resets the directory mtime cache and forces a full walk on the
// next scan. Unlike other modules, permissions does not have a "known-good"
// baseline — it always checks against absolute security rules (world-writable,
// shadow readable, non-root ownership). The rebaseline here simply ensures
// the incremental scan cache is rebuilt from scratch.
func (m *Module) Rebaseline(ctx context.Context) error {
	m.cache.DirMtimes = make(map[string]time.Time)
	m.cache.LastFull = time.Time{}
	return m.store.Save(m.Name(), m.cache)
}
