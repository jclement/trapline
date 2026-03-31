// Package users implements a user and group account monitoring scanner for Trapline.
//
// # What It Monitors and Why
//
// This module tracks all local user accounts (/etc/passwd), groups (/etc/group),
// and sudoers configuration (/etc/sudoers and /etc/sudoers.d/*). Account
// manipulation is one of the most reliable persistence techniques because it
// survives reboots, is difficult to detect without monitoring, and gives
// attackers native-looking access to the system.
//
// # How It Works
//
// On each scan, the module takes a "snapshot" by parsing three data sources:
//
//  1. /etc/passwd: Parsed line-by-line in standard colon-delimited format
//     (name:x:uid:gid:gecos:home:shell). Tracks username, UID, GID, home
//     directory, and login shell.
//
//  2. /etc/group: Parsed line-by-line (name:x:gid:member1,member2,...). Tracks
//     group name, GID, and member lists.
//
//  3. /etc/sudoers + /etc/sudoers.d/*: SHA-256 hashed (content is not parsed).
//     Files in sudoers.d are sorted alphabetically before hashing for deterministic
//     comparison. All hashes are concatenated into a single composite hash so any
//     change to any sudoers file is detected.
//
// On first run, the snapshot is saved as the baseline. Subsequent scans compare
// the current snapshot against the baseline and report differences.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - Persistence via Account Creation (T1136.001): New local user accounts,
//     especially with UID 0 (root) which is Critical severity.
//   - Privilege Escalation via UID Manipulation (T1548): Existing user's UID
//     changed to 0 (or any other UID change).
//   - Persistence via Shell Change (T1098): User's shell changed from /sbin/nologin
//     to /bin/bash, enabling interactive login for previously non-interactive accounts.
//   - Privilege Escalation via Sudoers (T1548.003): Any modification to /etc/sudoers
//     or files in /etc/sudoers.d/ granting elevated privileges.
//   - Account Removal: Deletion of user accounts (could indicate evidence tampering).
//   - Group Manipulation (T1098): New groups created (potential privilege group setup).
//
// # What It Does NOT Catch (Known Limitations)
//
//   - LDAP/AD/SSSD users: Only local accounts in /etc/passwd are monitored.
//     Centrally managed accounts are invisible to this module.
//   - Group membership changes: The module detects new groups but does not
//     currently diff the member lists of existing groups (e.g., adding a user
//     to the "docker" or "wheel" group).
//   - /etc/shadow changes: Password hash changes are not tracked (the fileintegrity
//     module covers shadow file changes). This module focuses on account structure.
//   - Removed groups: Only new groups are detected; group deletion is not flagged.
//   - SSH authorized_keys: Per-user SSH keys are not tracked here (use the
//     fileintegrity module with watch_extra paths for that).
//   - Sudoers semantic changes: The module hashes sudoers files but does not parse
//     the sudoers syntax, so it cannot distinguish between dangerous and benign
//     sudoers modifications.
//
// # False Positive Risks
//
//   - Legitimate user account creation by sysadmins or provisioning tools.
//   - Package installations that create system users (e.g., "postgres", "redis").
//   - Configuration management tools (Ansible, Puppet) modifying sudoers.
//   - Mitigation: Rebaseline after planned account changes. New system users
//     from packages typically have high UIDs and /sbin/nologin shells, which
//     helps triage.
//
// # Performance Characteristics
//
//   - I/O: Two file reads (passwd, group) plus one or more file reads for sudoers.
//     All files are small (typically < 10 KB). No recursive directory traversal.
//   - CPU: Minimal. Line parsing and SHA-256 hashing of small files.
//   - Memory: Proportional to the number of users and groups (typically dozens to
//     low hundreds of entries).
//
// # Configuration Options
//
//   - Currently no user-configurable settings. File paths (PasswdPath, GroupPath,
//     SudoersPath, SudoersDirPath) are overridable for testing.
package users

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jclement/trapline/internal/baseline"
	"github.com/jclement/trapline/internal/engine"
	"github.com/jclement/trapline/pkg/finding"
)

// UserEntry represents a single user account parsed from /etc/passwd.
// Fields correspond to the standard passwd(5) format:
// name:password:uid:gid:gecos:home:shell
type UserEntry struct {
	Name  string `json:"name"`
	UID   string `json:"uid"`
	GID   string `json:"gid"`
	Shell string `json:"shell"`
	Home  string `json:"home"`
}

// GroupEntry represents a single group parsed from /etc/group.
// Fields correspond to the standard group(5) format:
// name:password:gid:member1,member2,...
type GroupEntry struct {
	Name    string   `json:"name"`
	GID     string   `json:"gid"`
	Members []string `json:"members"`
}

// UsersBaseline is the composite snapshot of all account-related data.
// SudoersHash is a concatenation of SHA-256 hashes of /etc/sudoers and all
// files in /etc/sudoers.d/ (sorted alphabetically for determinism).
type UsersBaseline struct {
	Users       []UserEntry  `json:"users"`
	Groups      []GroupEntry `json:"groups"`
	SudoersHash string       `json:"sudoers_hash"`
}

// Module is the user/group account monitoring scanner. It tracks changes to
// local accounts, groups, and sudoers configuration.
type Module struct {
	store          *baseline.Store
	baseline       UsersBaseline
	baselineLoaded bool
	// Exported paths allow unit tests to point at fixture files instead of
	// the real /etc/ filesystem.
	PasswdPath     string
	GroupPath      string
	SudoersPath    string
	SudoersDirPath string
}

// New creates a Module with default /etc paths. Call Init() before use.
func New() *Module {
	return &Module{
		PasswdPath:     "/etc/passwd",
		GroupPath:      "/etc/group",
		SudoersPath:    "/etc/sudoers",
		SudoersDirPath: "/etc/sudoers.d",
	}
}

// Name returns the module identifier used for baseline storage and finding IDs.
func (m *Module) Name() string { return "users" }

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

// Scan takes a snapshot of current users, groups, and sudoers, then compares
// against the baseline. It detects: new users, removed users, UID changes,
// shell changes, new groups, and sudoers modifications.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.snapshot()
	if err != nil {
		return nil, err
	}

	// Learning mode: save current state as baseline, produce no findings.
	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		_ = m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding

	// --- User account comparison ---
	baseUsers := usersToMap(m.baseline.Users)
	curUsers := usersToMap(current.Users)

	for name, cur := range curUsers {
		if base, ok := baseUsers[name]; ok {
			// Existing user: check for UID changes. Any UID change is Critical
			// because it fundamentally changes what the user can access. UID 0
			// specifically means root-equivalent access.
			if cur.UID != base.UID {
				sev := finding.SeverityCritical
				if cur.UID == "0" {
					sev = finding.SeverityCritical
				}
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "user-uid-changed:" + name,
					Severity:  sev,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("user '%s' UID changed from %s to %s", name, base.UID, cur.UID),
					Detail:    map[string]interface{}{"user": name, "old_uid": base.UID, "new_uid": cur.UID},
				})
			}
			// Shell change: an attacker may change a service account from
			// /sbin/nologin to /bin/bash to enable interactive login.
			if cur.Shell != base.Shell {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "user-shell-changed:" + name,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("user '%s' shell changed from %s to %s", name, base.Shell, cur.Shell),
					Detail:    map[string]interface{}{"user": name, "old_shell": base.Shell, "new_shell": cur.Shell},
				})
			}
		} else {
			// New user account. High severity by default; Critical if UID is 0
			// because a UID-0 account has full root privileges regardless of name.
			sev := finding.SeverityHigh
			if cur.UID == "0" {
				sev = finding.SeverityCritical
			}
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "user-added:" + name,
				Severity:  sev,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new user '%s' added (UID %s)", name, cur.UID),
				Detail:    map[string]interface{}{"user": name, "uid": cur.UID, "shell": cur.Shell, "home": cur.Home},
			})
		}
	}

	// Detect removed users. This is High severity because user removal could
	// indicate evidence tampering (deleting a compromised account to hide tracks)
	// or unauthorized system modification.
	for name := range baseUsers {
		if _, ok := curUsers[name]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "user-removed:" + name,
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("user '%s' removed", name),
				Detail:    map[string]interface{}{"user": name},
			})
		}
	}

	// --- Group comparison ---
	// Currently only detects new groups. Future enhancement: diff member lists
	// to catch users added to privileged groups (docker, wheel, sudo, etc.).
	baseGroups := groupsToMap(m.baseline.Groups)
	curGroups := groupsToMap(current.Groups)

	for name, cur := range curGroups {
		if _, ok := baseGroups[name]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "group-added:" + name,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new group '%s' added", name),
				Detail:    map[string]interface{}{"group": name, "gid": cur.GID},
			})
		}
	}

	// --- Sudoers comparison ---
	// Any change to sudoers is High severity because it can grant root access.
	// The hash covers both /etc/sudoers and all files in /etc/sudoers.d/.
	if current.SudoersHash != m.baseline.SudoersHash && current.SudoersHash != "" {
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "sudoers-modified",
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   "sudoers file modified",
			Detail:    map[string]interface{}{"baseline_hash": m.baseline.SudoersHash, "current_hash": current.SudoersHash},
		})
	}

	return findings, nil
}

// Rebaseline captures the current account state as the new baseline.
// Call this after planned account changes to prevent false positives.
func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.snapshot()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

// snapshot collects the current state of all monitored account data.
// The sudoers hash is a concatenation of individual file hashes (not a hash
// of hashes) to ensure any single-file change is detectable. Files in
// sudoers.d are sorted alphabetically before hashing so the composite hash
// is deterministic regardless of filesystem readdir order.
func (m *Module) snapshot() (UsersBaseline, error) {
	users, err := parsePasswd(m.PasswdPath)
	if err != nil {
		return UsersBaseline{}, fmt.Errorf("reading passwd: %w", err)
	}

	groups, err := parseGroup(m.GroupPath)
	if err != nil {
		groups = nil // non-fatal: some systems may have restricted /etc/group
	}

	// Hash the main sudoers file
	sudoersHash := hashFile(m.SudoersPath)

	// Also hash all files in sudoers.d/. The sort ensures deterministic ordering
	// because os.ReadDir returns entries in filesystem order which may vary.
	if entries, err := os.ReadDir(m.SudoersDirPath); err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			h := hashFile(filepath.Join(m.SudoersDirPath, name))
			if h != "" {
				sudoersHash += h
			}
		}
	}

	return UsersBaseline{
		Users:       users,
		Groups:      groups,
		SudoersHash: sudoersHash,
	}, nil
}

// parsePasswd reads /etc/passwd and returns all user entries.
// Format: name:password:uid:gid:gecos:home:shell (7 colon-delimited fields).
// Comment lines (starting with #) and blank lines are skipped.
func parsePasswd(path string) ([]UserEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var users []UserEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// SplitN with limit 7 handles shells containing colons (unlikely but safe)
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			continue
		}
		users = append(users, UserEntry{
			Name:  fields[0], // username
			UID:   fields[2], // user ID (string to preserve leading zeros if any)
			GID:   fields[3], // primary group ID
			Home:  fields[5], // home directory
			Shell: fields[6], // login shell
		})
	}
	return users, scanner.Err()
}

// parseGroup reads /etc/group and returns all group entries.
// Format: name:password:gid:member1,member2,... (4 colon-delimited fields).
func parseGroup(path string) ([]GroupEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var groups []GroupEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		// Members field is comma-separated; empty string means no members
		var members []string
		if fields[3] != "" {
			members = strings.Split(fields[3], ",")
		}
		groups = append(groups, GroupEntry{
			Name:    fields[0], // group name
			GID:     fields[2], // group ID
			Members: members,   // supplementary members (primary members are implicit)
		})
	}
	return groups, scanner.Err()
}

// hashFile computes the SHA-256 hex digest of a file's contents.
// Returns empty string if the file cannot be read (e.g., does not exist or
// permission denied). This is intentional -- a missing sudoers file is not
// an error condition (some systems use other privilege escalation mechanisms).
func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

// usersToMap converts a slice of UserEntry into a map keyed by username
// for efficient O(1) lookups during baseline comparison.
func usersToMap(users []UserEntry) map[string]UserEntry {
	m := make(map[string]UserEntry)
	for _, u := range users {
		m[u.Name] = u
	}
	return m
}

// groupsToMap converts a slice of GroupEntry into a map keyed by group name
// for efficient O(1) lookups during baseline comparison.
func groupsToMap(groups []GroupEntry) map[string]GroupEntry {
	m := make(map[string]GroupEntry)
	for _, g := range groups {
		m[g.Name] = g
	}
	return m
}
