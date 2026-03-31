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
}

// New creates an SSH scanner with the default config path. The caller can
// override ConfigPath before calling Init if needed.
func New() *Module {
	return &Module{
		ConfigPath: "/etc/ssh/sshd_config",
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
