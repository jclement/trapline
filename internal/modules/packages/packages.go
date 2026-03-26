// Package packages monitors the integrity of files installed by the system
// package manager (dpkg/apt) by detecting modifications made outside of
// normal package operations.
//
// # What it monitors and why
//
// Package integrity monitoring catches binary replacement attacks — one of the
// most serious post-exploitation techniques. After gaining root access, attackers
// commonly replace system binaries (e.g., /usr/sbin/sshd, /usr/bin/sudo,
// /usr/bin/login) with trojaned versions that include backdoors, credential
// harvesting, or persistence mechanisms. If /usr/sbin/sshd has been modified
// outside of apt, something is very wrong.
//
// This module uses dpkg's own verification database as the ground truth rather
// than maintaining independent file hashes. This is both simpler (dpkg already
// stores MD5 checksums for every installed file) and more robust (the baseline
// automatically updates when packages are legitimately upgraded via apt).
//
// # How it works
//
// The module runs `dpkg --verify`, which compares every installed file against
// the checksums stored in /var/lib/dpkg/info/*.md5sums. The output uses an
// rpm-style format where each character position indicates a specific type of
// change:
//
//	??5??????   /path/to/file
//
// Position meanings: S=size, M=mode, 5=MD5sum, D=device, L=link, U=user,
// G=group, T=mtime. A '?' means the check could not be performed.
//
// The module parses this output and generates a finding for each modified file
// (after applying exclusion filters).
//
// # What it catches
//
//   - Backdoored system binaries (replaced sshd, sudo, login, su, etc.)
//   - Rootkit-modified libraries (trojaned libc, libpam, libssl)
//   - Tampered configuration files installed by packages (outside /etc)
//   - Corrupted binaries from disk errors or failed partial updates
//   - MITRE ATT&CK: T1554 (Compromise Client Software Binary), T1543.002
//     (Systemd Service modification), T1036.005 (Match Legitimate Name or Location)
//
// # What it does NOT catch (known limitations)
//
//   - Only works on Debian/Ubuntu systems with dpkg. RPM-based systems (RHEL,
//     Fedora) would need rpm --verify instead (not implemented).
//   - Files not managed by any package (manually installed binaries, scripts in
//     /usr/local/bin) are invisible to this check.
//   - The dpkg MD5 checksums are stored on the same filesystem as the binaries.
//     An attacker with root access could update the checksums to match their
//     trojaned binaries. Defense-in-depth: compare against remote/offline backups.
//   - Configuration files in /etc are excluded by default because dpkg expects
//     admins to modify them (dpkg marks them as "conffiles" with special handling).
//   - Does not detect added files — only modified or removed package-managed files.
//     An attacker could add new binaries without triggering this check.
//   - dpkg --verify uses MD5, which is cryptographically broken. A sophisticated
//     attacker could craft a binary with the same MD5 as the original. In practice,
//     this is extremely difficult for ELF binaries and has not been observed in
//     the wild.
//
// # False positive risks
//
//   - Files legitimately modified by administrators outside apt (e.g., manually
//     patched binaries, custom-compiled replacements) will generate findings.
//   - Some packages modify their own files post-install via maintainer scripts
//     in ways that dpkg --verify detects as changes.
//   - Running scans during an active apt upgrade may catch partially-written files.
//   - /etc is excluded by default to avoid the flood of expected config changes;
//     additional exclusions can be added via configuration.
//
// # Performance characteristics
//
// Forks a `dpkg --verify` subprocess that reads MD5 checksums from
// /var/lib/dpkg/info/*.md5sums and stats/checksums every installed file. On a
// typical server with ~30,000 package-managed files, this takes 5-30 seconds
// depending on disk speed and cache state. CPU usage is moderate (MD5 hashing).
// The module does not cache results between scans because the ground truth
// (dpkg database) updates automatically with package operations.
//
// # Configuration options
//
// Via engine.ModuleConfig.Settings:
//
//   - "exclude_paths" ([]string): Additional path prefixes to exclude from findings.
//     These are appended to the default exclusion of "/etc/". Use this for paths
//     where legitimate out-of-band modifications are expected.
package packages

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// Module implements engine.Scanner for dpkg package integrity verification.
type Module struct {
	store        *baseline.Store
	excludePaths []string // Path prefixes to ignore in dpkg --verify output
	// VerifyCmd is an injectable function for running the verification command.
	// In production this is nil (uses dpkg --verify). Tests inject a mock to
	// avoid requiring dpkg and a real package database.
	VerifyCmd func(ctx context.Context) ([]byte, error)
}

// New creates a packages scanner with /etc/ excluded by default. Config files
// in /etc are expected to diverge from package-installed versions because
// administrators routinely customize them. Including /etc would generate
// hundreds of noisy, expected findings on every scan.
func New() *Module {
	return &Module{
		excludePaths: []string{"/etc/"},
	}
}

func (m *Module) Name() string { return "packages" }

// Init loads the baseline store and applies any user-configured exclusion paths.
// User-provided exclusions are appended to (not replacing) the default /etc/
// exclusion, so the default is always preserved.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store

	// Allow users to add exclusion prefixes for paths where out-of-band
	// modifications are expected (e.g., custom-compiled replacements in
	// specific directories). These are appended to the defaults.
	if paths, ok := cfg.Settings["exclude_paths"]; ok {
		if ps, ok := paths.([]interface{}); ok {
			for _, p := range ps {
				if s, ok := p.(string); ok {
					m.excludePaths = append(m.excludePaths, s)
				}
			}
		}
	}

	return nil
}

// Scan runs dpkg --verify and parses the output to find package-managed files
// that have been modified outside of the package manager.
//
// If dpkg is not available (e.g., on RPM-based systems or minimal containers),
// the scan returns no findings and no error — this is expected and not a failure.
//
// Each line of dpkg --verify output represents a modified file. The format is:
//
//	??5??????   /path/to/file
//
// where each character position indicates a type of change (5 = MD5 checksum
// differs, S = size differs, etc.). We report any line as a finding, regardless
// of which specific attributes changed, because any deviation from the package
// database is potentially suspicious.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	output, err := m.runVerify(ctx)
	if err != nil {
		// dpkg not available — this is expected on non-Debian systems or
		// minimal containers. Silently return no findings.
		return nil, nil
	}

	var findings []finding.Finding
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// dpkg --verify lines are at least 12 characters: 9-char status field,
		// whitespace separator, and a file path. Short lines are malformed or
		// informational — skip them.
		if len(line) < 12 {
			continue
		}

		// dpkg --verify output format: "??5??????   /path/to/file"
		// The status field and path are separated by whitespace. We take the
		// last field as the path to handle any amount of whitespace.
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Use the last field as the path — dpkg --verify always puts the
		// file path as the final field on each line.
		path := parts[len(parts)-1]

		// Apply exclusion filters. /etc/ is excluded by default because config
		// files are expected to be modified by administrators. Additional
		// exclusions can be added via configuration.
		excluded := false
		for _, excl := range m.excludePaths {
			if strings.HasPrefix(path, excl) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		// Every non-excluded modified file is a high-severity finding. We use
		// high (not critical) because there are legitimate edge cases (e.g.,
		// files modified by post-install scripts). The operator should
		// investigate each finding.
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "package-file-modified:" + path,
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("package file modified outside package manager: %s", path),
			Detail: map[string]interface{}{
				"path":   path,
				"status": parts[0], // The 9-character status field showing what changed
			},
		})
	}

	return findings, nil
}

// Rebaseline is a no-op for the packages module. Unlike other modules that
// maintain their own baselines, this module compares against dpkg's built-in
// package database (/var/lib/dpkg/info/*.md5sums). That database is automatically
// updated whenever packages are installed, upgraded, or removed via apt/dpkg,
// so there is no separate baseline to manage.
func (m *Module) Rebaseline(ctx context.Context) error {
	return nil
}

// runVerify executes dpkg --verify and returns the raw output. The VerifyCmd
// function pointer allows tests to inject mock output without requiring a
// real dpkg installation.
//
// dpkg --verify returns a non-zero exit code when modifications are found,
// which Go's exec treats as an error. We handle this by checking for ExitError
// and returning the combined stdout+stderr output anyway, since the non-zero
// exit is expected behavior (it means "I found differences"), not a failure.
func (m *Module) runVerify(ctx context.Context) ([]byte, error) {
	if m.VerifyCmd != nil {
		return m.VerifyCmd(ctx)
	}
	cmd := exec.CommandContext(ctx, "dpkg", "--verify")
	output, err := cmd.Output()
	if err != nil {
		// dpkg --verify returns exit code 1+ when it finds modifications.
		// This is expected behavior, not an error — extract the output.
		if exitErr, ok := err.(*exec.ExitError); ok {
			return append(output, exitErr.Stderr...), nil
		}
		// Non-ExitError means dpkg is not installed or cannot run at all.
		return nil, err
	}
	return output, nil
}
