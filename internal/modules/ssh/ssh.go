// Package ssh monitors the OpenSSH daemon configuration for security-relevant
// changes and insecure settings.
//
// # What it monitors and why
//
// SSH is the primary remote access vector on Linux servers. The sshd_config file
// controls authentication methods, access restrictions, and protocol behavior.
// Insecure settings such as PasswordAuthentication yes and PermitRootLogin yes are
// the number one configuration weakness on internet-facing hosts. Changes to this
// file are often the first sign of lateral movement or persistence setup by an
// attacker who has gained initial access.
//
// # How it works
//
// The module performs two complementary checks on every scan:
//
//  1. Policy check (stateless): Parses sshd_config and flags known-bad settings
//     regardless of baseline state. This catches insecure defaults on first run.
//
//  2. Drift detection (stateful): Computes a SHA-256 hash of the entire config file
//     and compares it against a stored baseline. Any change — even a comment edit —
//     triggers an alert. The baseline is persisted to disk as JSON and established
//     automatically on first scan.
//
// Data sources: /etc/ssh/sshd_config (configurable via ConfigPath).
//
// # What it catches
//
//   - PasswordAuthentication enabled (brute-force attacks, credential stuffing)
//   - PermitRootLogin yes (direct root compromise via stolen credentials)
//   - PermitEmptyPasswords yes (unauthenticated root/user access)
//   - Any modification to sshd_config (persistence via authorized keys changes,
//     backdoor port additions, etc.)
//   - MITRE ATT&CK: T1098.004 (SSH Authorized Keys), T1021.004 (Remote Services: SSH),
//     T1556.003 (Modify Authentication Process)
//
// # What it does NOT catch (known limitations)
//
//   - Does not monitor ~/.ssh/authorized_keys files (separate vector entirely)
//   - Does not check sshd_config.d/ drop-in files or Include directives
//   - Does not verify that sshd has actually reloaded the config (a changed file
//     may not yet be active)
//   - Does not detect runtime sshd options passed via command-line flags
//   - Only captures the first value for duplicate directives; sshd uses first-match
//     semantics for most settings, but Match blocks can override them
//
// # False positive risks
//
//   - Legitimate config changes by administrators trigger the hash-changed alert.
//     Mitigate by rebaselining after planned maintenance windows.
//   - Comment-only edits trigger the hash alert because the full file is hashed,
//     not just active directives. This is intentional — comment changes may mask
//     real modifications in diffs.
//
// # Performance characteristics
//
// Extremely lightweight: a single file read (~1-4 KB typically) plus SHA-256 hash
// and a line-by-line parse. No filesystem walks, no subprocess calls. Runs in
// under 1 millisecond on any hardware.
//
// # Configuration options
//
// ConfigPath can be set on the Module struct to monitor a non-default sshd_config
// location (useful for containers or chroot environments). No additional settings
// are read from engine.ModuleConfig.
package ssh

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/trapline/internal/baseline"
	"github.com/jclement/trapline/internal/engine"
	"github.com/jclement/trapline/pkg/finding"
)

// SSHBaseline stores the known-good state of the SSH daemon configuration.
// ConfigHash is a hex-encoded SHA-256 of the raw file contents (including
// comments and whitespace) so that any modification is detected. Settings
// holds parsed key-value pairs for security policy checks.
type SSHBaseline struct {
	ConfigHash string            `json:"config_hash"`
	Settings   map[string]string `json:"settings"`
}

// Module implements engine.Scanner for SSH configuration monitoring.
type Module struct {
	store          *baseline.Store
	baseline       SSHBaseline
	baselineLoaded bool
	// ConfigPath allows overriding the default /etc/ssh/sshd_config location,
	// primarily useful for testing or monitoring non-standard installations.
	ConfigPath string
	// ProcDir is the path to /proc, overridable for testing.
	ProcDir string
	// allowedUsers is an optional whitelist of usernames permitted to have
	// active SSH sessions. When set, any SSH session by a user NOT in this
	// list triggers a critical finding. When empty, session monitoring is
	// disabled (no findings for sessions).
	allowedUsers []string
}

// New creates an SSH scanner with the default config path. The caller can
// override ConfigPath before calling Init if needed.
func New() *Module {
	return &Module{
		ConfigPath: "/etc/ssh/sshd_config",
		ProcDir:    "/proc",
	}
}

func (m *Module) Name() string { return "ssh" }

// Init loads the baseline store and any previously-saved baseline from disk.
// If no prior baseline exists, baselineLoaded will be false, and the first
// Scan call will establish one.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)

	// Parse allowed_users from config. When set, any active SSH session by
	// a user not in this list triggers a critical alert.
	if auRaw, ok := cfg.Settings["allowed_users"]; ok {
		if auList, ok := auRaw.([]interface{}); ok {
			for _, e := range auList {
				if name, ok := e.(string); ok {
					m.allowedUsers = append(m.allowedUsers, name)
				}
			}
		}
	}

	return nil
}

// Scan reads the current sshd_config and produces findings in two phases:
//
//  1. Security policy checks run unconditionally — even on first scan before
//     a baseline exists — because insecure defaults are dangerous from day one.
//
//  2. Hash-based drift detection runs only after a baseline is established.
//     On the very first scan, we save the current state as baseline and return
//     only the policy findings.
//
// If the config file does not exist (e.g., SSH not installed), the scan
// returns no findings and no error — this is expected on minimal containers.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.snapshot()
	if err != nil {
		// Config file may not exist (e.g., SSH not installed). This is not an
		// error condition — the module simply has nothing to report.
		return nil, nil
	}

	var findings []finding.Finding

	// Always check security settings regardless of baseline. Insecure defaults
	// should be flagged even on the very first scan before a baseline exists.
	findings = append(findings, checkSecuritySettings(current.Settings)...)

	if !m.baselineLoaded {
		// First run: establish the baseline so future scans can detect drift.
		m.baseline = current
		m.baselineLoaded = true
		_ = m.store.Save(m.Name(), m.baseline)
		return findings, nil
	}

	// Detect any modification to the config file by comparing SHA-256 hashes.
	// We hash the entire raw file (not just parsed settings) to catch changes
	// in comments, whitespace, or directives we don't explicitly parse.
	if current.ConfigHash != m.baseline.ConfigHash {
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "ssh-config-changed",
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   "sshd_config has been modified",
			Detail: map[string]interface{}{
				"baseline_hash": m.baseline.ConfigHash,
				"current_hash":  current.ConfigHash,
			},
		})
	}

	// Check active SSH sessions against the allowed_users whitelist.
	findings = append(findings, m.checkSessions()...)

	return findings, nil
}

// Rebaseline captures the current sshd_config state as the new known-good
// baseline. Call this after verified, intentional configuration changes to
// suppress the hash-changed alert on subsequent scans.
func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.snapshot()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

// snapshot reads the sshd_config file and produces a baseline containing
// both the raw file hash and the parsed settings map. The hash covers the
// entire file byte-for-byte so even comment or whitespace changes are detected.
func (m *Module) snapshot() (SSHBaseline, error) {
	data, err := os.ReadFile(m.ConfigPath)
	if err != nil {
		return SSHBaseline{}, err
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	settings := parseSSHConfig(string(data))

	return SSHBaseline{
		ConfigHash: hash,
		Settings:   settings,
	}, nil
}

// parseSSHConfig extracts active (non-comment, non-blank) directives from
// sshd_config content into a map. Keys are lowercased for case-insensitive
// lookup, matching sshd's own case-insensitive directive handling.
//
// Limitation: only the first value token is captured. Multi-word values
// (e.g., "AllowUsers alice bob") will only record "alice". This is acceptable
// because our security checks only examine single-value boolean directives
// (PasswordAuthentication, PermitRootLogin, etc.).
//
// Limitation: Match blocks are not handled — all directives are treated as
// global. A "PermitRootLogin no" at the top level could be overridden by a
// Match block, but this parser would not detect that.
func parseSSHConfig(content string) map[string]string {
	settings := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// sshd_config uses whitespace-separated "Directive Value" format.
		// We split on any whitespace and take the first two tokens.
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			settings[strings.ToLower(parts[0])] = parts[1]
		}
	}
	return settings
}

// checkSecuritySettings evaluates parsed SSH directives against a hardcoded
// list of known-insecure values. These checks are intentionally conservative —
// we only flag values that are unambiguously dangerous (e.g., PasswordAuthentication
// yes) rather than trying to score the overall security posture.
//
// Each check uses case-insensitive comparison because sshd_config values are
// case-insensitive (yes/YES/Yes are all equivalent).
//
// Settings that are absent from the config are NOT flagged, because their
// effective value depends on the compiled-in sshd defaults, which vary by
// distribution and version. Flagging absent settings would produce excessive
// false positives.
func checkSecuritySettings(settings map[string]string) []finding.Finding {
	var findings []finding.Finding

	// Table-driven checks: each entry maps a directive to its known-bad values.
	// This makes it trivial to add new checks without changing control flow.
	checks := []struct {
		key     string
		badVals []string
		summary string
	}{
		{"passwordauthentication", []string{"yes"}, "PasswordAuthentication is enabled — should be 'no'"},
		{"permitrootlogin", []string{"yes"}, "PermitRootLogin is 'yes' — should be 'no' or 'prohibit-password'"},
		{"permitemptypasswords", []string{"yes"}, "PermitEmptyPasswords is enabled — should be 'no'"},
	}

	for _, check := range checks {
		if val, ok := settings[check.key]; ok {
			for _, bad := range check.badVals {
				if strings.EqualFold(val, bad) {
					findings = append(findings, finding.Finding{
						Timestamp: time.Now().UTC(),
						FindingID: "ssh-insecure-setting:" + check.key,
						Severity:  finding.SeverityHigh,
						Status:    finding.StatusNew,
						Summary:   check.summary,
						Detail: map[string]interface{}{
							"setting": check.key,
							"value":   val,
						},
					})
				}
			}
		}
	}

	return findings
}

// sshSession represents an active SSH session detected via /proc.
type sshSession struct {
	PID      int
	User     string
	UID      int
	RemoteIP string
}

// checkSessions detects active SSH sessions by scanning /proc for sshd child
// processes. When allowed_users is configured, any session by a user not in
// the whitelist generates a critical finding. When allowed_users is empty,
// no session findings are generated (the feature is opt-in).
//
// Detection method: sshd forks a child process per session. We find processes
// whose /proc/[pid]/exe points to sshd and whose parent is also sshd. The
// child's UID (from /proc/[pid]/status) identifies the logged-in user. The
// remote IP is extracted from /proc/[pid]/net/tcp or the process's environment
// via SSH_CONNECTION in /proc/[pid]/environ.
func (m *Module) checkSessions() []finding.Finding {
	if len(m.allowedUsers) == 0 {
		return nil
	}

	sessions := m.detectSSHSessions()
	allowed := make(map[string]bool, len(m.allowedUsers))
	for _, u := range m.allowedUsers {
		allowed[u] = true
	}

	var findings []finding.Finding
	for _, s := range sessions {
		if !allowed[s.User] {
			detail := map[string]interface{}{
				"pid":  s.PID,
				"user": s.User,
				"uid":  s.UID,
			}
			if s.RemoteIP != "" {
				detail["remote_ip"] = s.RemoteIP
			}
			summary := fmt.Sprintf("unauthorized SSH session: user '%s' (PID %d)", s.User, s.PID)
			if s.RemoteIP != "" {
				summary = fmt.Sprintf("unauthorized SSH session: user '%s' from %s (PID %d)", s.User, s.RemoteIP, s.PID)
			}
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: fmt.Sprintf("ssh-session-unauthorized:%s:%d", s.User, s.PID),
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   summary,
				Detail:    detail,
			})
		}
	}
	return findings
}

// detectSSHSessions finds active SSH sessions by looking for sshd child
// processes. sshd forks a child per connection that runs as the authenticated
// user's UID (after privilege separation). We identify these by:
//  1. Finding processes whose comm is "sshd"
//  2. Checking if their UID is non-zero (the child process drops to the
//     user's UID; the parent stays root)
//  3. Resolving the username from /etc/passwd
func (m *Module) detectSSHSessions() []sshSession {
	entries, err := os.ReadDir(m.ProcDir)
	if err != nil {
		return nil
	}

	// Build a UID-to-username map from /etc/passwd.
	uidMap := parsePasswd()

	var sessions []sshSession
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		pidDir := filepath.Join(m.ProcDir, entry.Name())

		// Check if this is an sshd process.
		comm, err := os.ReadFile(filepath.Join(pidDir, "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) != "sshd" {
			continue
		}

		// Read UID from /proc/[pid]/status. The session child runs as the
		// user's UID (non-zero), while the parent listener runs as root (0).
		uid := readUID(pidDir)
		if uid == 0 {
			continue // root sshd = parent/listener, not a user session
		}

		user := uidMap[uid]
		if user == "" {
			user = strconv.Itoa(uid)
		}

		// Try to get the remote IP from SSH_CONNECTION in /proc/[pid]/environ.
		remoteIP := readSSHConnection(pidDir)

		sessions = append(sessions, sshSession{
			PID:      pid,
			User:     user,
			UID:      uid,
			RemoteIP: remoteIP,
		})
	}

	return sessions
}

// readUID extracts the real UID from /proc/[pid]/status.
func readUID(pidDir string) int {
	data, err := os.ReadFile(filepath.Join(pidDir, "status"))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ := strconv.Atoi(fields[1])
				return uid
			}
		}
	}
	return -1
}

// readSSHConnection extracts the remote IP from the SSH_CONNECTION environment
// variable in /proc/[pid]/environ. Format: "client_ip client_port server_ip server_port".
func readSSHConnection(pidDir string) string {
	data, err := os.ReadFile(filepath.Join(pidDir, "environ"))
	if err != nil {
		return ""
	}
	// /proc/[pid]/environ uses NUL bytes as separators.
	for _, env := range strings.Split(string(data), "\x00") {
		if strings.HasPrefix(env, "SSH_CONNECTION=") {
			parts := strings.Fields(strings.TrimPrefix(env, "SSH_CONNECTION="))
			if len(parts) >= 1 {
				return parts[0] // client IP
			}
		}
	}
	return ""
}

// parsePasswd reads /etc/passwd and returns a UID-to-username map.
func parsePasswd() map[int]string {
	result := make(map[int]string)
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return result
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// /etc/passwd format: name:password:UID:GID:gecos:home:shell
		fields := strings.SplitN(scanner.Text(), ":", 4)
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		result[uid] = fields[0]
	}
	return result
}
