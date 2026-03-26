// doctor.go implements the "trapline doctor" health-check framework. It runs a
// suite of checks organized by category (Binary, Config, Systemd, Directories,
// Baselines, Output, Apt) to verify that a Trapline installation is healthy
// and correctly configured.
//
// Each check returns one of three statuses:
//
//   - CheckPassed:  the check succeeded; everything is as expected.
//   - CheckWarning: something is sub-optimal but Trapline can still function
//     (e.g. config is world-readable, baselines are stale, TCP sink unreachable).
//   - CheckError:   a critical problem that will prevent Trapline from running
//     correctly (e.g. binary missing, config invalid, service not enabled).
//
// Every check also returns an optional Fix string — a human-readable command
// or instruction that would resolve the issue. This lays the groundwork for a
// future "--fix" flag that could automatically apply these fixes: the Doctor
// function would iterate the results, and for each CheckError/CheckWarning
// with a non-empty Fix, execute the suggested remediation.
//
// Output formatting groups checks by category with Unicode status indicators
// (checkmark, warning triangle, cross) for quick visual scanning. The summary
// line at the end provides a tally of passed/warning/error counts.

package install

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DoctorResult holds the aggregated results of all health checks. After
// [Doctor] runs, Checks contains every individual result and the Passed,
// Warnings, and Errors counters provide a quick summary.
type DoctorResult struct {
	Checks   []Check // all individual check results in execution order
	Passed   int     // count of checks with CheckPassed status
	Warnings int     // count of checks with CheckWarning status
	Errors   int     // count of checks with CheckError status
}

// Check represents a single doctor check result. Every check belongs to a
// Category (used for grouping in output), has a human-readable Name, a
// Status (pass/warn/error), a Detail string describing what was found, and
// an optional Fix string with remediation instructions.
type Check struct {
	Category string      // grouping label: "Binary", "Config", "Systemd", etc.
	Name     string      // human-readable check name, e.g. "Config is valid YAML"
	Status   CheckStatus // pass/warning/error result
	Detail   string      // what was found, e.g. "Config permissions 0600"
	Fix      string      // suggested fix command (empty if passed or no fix known)
}

// CheckStatus is an enum representing the outcome of a single health check.
// The iota ordering (Passed=0, Warning=1, Error=2) is deliberate so that
// higher values indicate more severe problems.
type CheckStatus int

const (
	// CheckPassed indicates the check found no issues.
	CheckPassed CheckStatus = iota

	// CheckWarning indicates a non-critical issue that should be addressed
	// but does not prevent Trapline from functioning.
	CheckWarning

	// CheckError indicates a critical issue that will prevent Trapline from
	// running correctly. The Fix field should contain remediation steps.
	CheckError
)

// String returns a Unicode status indicator for terminal display:
// checkmark for passed, warning triangle for warning, cross for error.
func (s CheckStatus) String() string {
	switch s {
	case CheckPassed:
		return "✓"
	case CheckWarning:
		return "⚠"
	case CheckError:
		return "✗"
	}
	return "?"
}

// Doctor runs all health checks and returns the aggregated results. Checks
// are organized into the following categories:
//
// Binary checks:
//   - Binary exists at the canonical install path.
//   - Running as root (required for full system access).
//
// Config checks:
//   - Config file exists at /etc/trapline/trapline.yml.
//   - Config file contains valid YAML (catches syntax errors).
//   - Config file permissions are restrictive (not world-readable, since the
//     config may contain secrets like the dashboard publish secret).
//
// Systemd checks:
//   - Unit file is installed at the expected path.
//   - Service is enabled (will start on boot).
//   - Service is currently active (running).
//
// Directory checks:
//   - All required directories exist (config, state, baselines, logs).
//
// Baseline checks:
//   - At least one baseline file exists (indicates initial learning completed).
//   - No baseline files are older than 7 days (suggests stale data).
//
// Output checks:
//   - TCP sink at the default address is reachable (checks Fluent Bit etc.).
//
// Apt checks:
//   - APT hook is installed on Debian/Ubuntu systems.
func Doctor() *DoctorResult {
	r := &DoctorResult{}

	// ---- Binary & Installation ----
	// Verify the binary is installed at the expected path and we have
	// sufficient privileges for a complete health check.
	r.check("Binary", "Binary exists", func() (CheckStatus, string, string) {
		info, err := os.Stat(BinaryPath)
		if err != nil {
			return CheckError, "Binary not found at " + BinaryPath, "Run: trapline install"
		}
		return CheckPassed, fmt.Sprintf("Binary at %s (%d bytes)", BinaryPath, info.Size()), ""
	})

	r.check("Binary", "Running as root", func() (CheckStatus, string, string) {
		if os.Getuid() != 0 {
			return CheckWarning, "Not running as root — some checks may be incomplete", "Run: sudo trapline doctor"
		}
		return CheckPassed, "Running as root", ""
	})

	// ---- Configuration ----
	// Verify the config file exists, parses correctly, and has appropriate
	// permissions (should not be world-readable since it may contain secrets).
	r.check("Config", "Config file exists", func() (CheckStatus, string, string) {
		if _, err := os.Stat(ConfigPath); err != nil {
			return CheckError, "Config not found at " + ConfigPath, "Run: trapline install"
		}
		return CheckPassed, "Config file exists at " + ConfigPath, ""
	})

	r.check("Config", "Config is valid YAML", func() (CheckStatus, string, string) {
		data, err := os.ReadFile(ConfigPath)
		if err != nil {
			return CheckError, "Cannot read config: " + err.Error(), ""
		}
		var raw map[string]interface{}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return CheckError, "Invalid YAML: " + err.Error(), "Fix the syntax in " + ConfigPath
		}
		return CheckPassed, "Config is valid YAML", ""
	})

	r.check("Config", "Config permissions", func() (CheckStatus, string, string) {
		info, err := os.Stat(ConfigPath)
		if err != nil {
			return CheckError, "Cannot stat config", ""
		}
		mode := info.Mode().Perm()
		// Check if group or other have read access (bits 0044). The config
		// may contain the dashboard secret, so it should be 0600 (owner only).
		if mode&0044 != 0 {
			return CheckWarning, fmt.Sprintf("Config is readable by non-root (%04o)", mode), fmt.Sprintf("Run: chmod 600 %s", ConfigPath)
		}
		return CheckPassed, fmt.Sprintf("Config permissions %04o", mode), ""
	})

	// ---- Systemd ----
	// Verify the systemd unit is installed, enabled (starts on boot), and
	// currently active (running).
	r.check("Systemd", "Unit file installed", func() (CheckStatus, string, string) {
		if _, err := os.Stat(ServicePath); err != nil {
			return CheckError, "Systemd unit not found", "Run: trapline install"
		}
		return CheckPassed, "Unit file at " + ServicePath, ""
	})

	r.check("Systemd", "Service enabled", func() (CheckStatus, string, string) {
		out, err := exec.Command("systemctl", "is-enabled", "trapline").Output()
		if err != nil || strings.TrimSpace(string(out)) != "enabled" {
			return CheckError, "Service not enabled", "Run: systemctl enable trapline"
		}
		return CheckPassed, "Service is enabled", ""
	})

	r.check("Systemd", "Service active", func() (CheckStatus, string, string) {
		out, err := exec.Command("systemctl", "is-active", "trapline").Output()
		if err != nil || strings.TrimSpace(string(out)) != "active" {
			return CheckError, "Service not running", "Run: systemctl start trapline"
		}
		return CheckPassed, "Service is active (running)", ""
	})

	// ---- Directories ----
	// Verify all required directories exist. Missing directories typically
	// indicate an incomplete or failed installation.
	for _, dir := range []string{ConfigDir, StateDir, BaselinesDir, LogDir} {
		dirCopy := dir // capture loop variable for the closure
		r.check("Directories", dirCopy+" exists", func() (CheckStatus, string, string) {
			info, err := os.Stat(dirCopy)
			if err != nil {
				return CheckError, dirCopy + " not found", "Run: trapline install"
			}
			return CheckPassed, fmt.Sprintf("%s exists (%04o)", dirCopy, info.Mode().Perm()), ""
		})
	}

	// ---- Baselines ----
	// Check that baseline files exist (indicating initial learning is done)
	// and are reasonably fresh. Stale baselines may indicate that a module
	// has stopped running.
	r.check("Baselines", "Baseline files present", func() (CheckStatus, string, string) {
		entries, err := os.ReadDir(BaselinesDir)
		if err != nil {
			return CheckError, "Cannot read baselines dir", ""
		}
		count := 0
		var oldest time.Time
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				count++
				info, _ := e.Info()
				if info != nil {
					if oldest.IsZero() || info.ModTime().Before(oldest) {
						oldest = info.ModTime()
					}
				}
			}
		}
		if count == 0 {
			return CheckWarning, "No baseline files found — run trapline scan to initialize", ""
		}
		detail := fmt.Sprintf("%d baseline files", count)
		// Baselines older than 7 days may indicate a stalled module or an
		// operator who forgot to rebaseline after system changes.
		if !oldest.IsZero() && time.Since(oldest) > 7*24*time.Hour {
			return CheckWarning, detail + " (oldest > 7 days)", "Consider: trapline rebaseline"
		}
		return CheckPassed, detail, ""
	})

	// ---- Output sinks ----
	// Probe the default TCP sink address to verify that a log collector
	// (e.g. Fluent Bit) is listening. This is a warning, not an error,
	// because the TCP sink is disabled by default and may not be in use.
	r.check("Output", "TCP sink reachable", func() (CheckStatus, string, string) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:51888", 2*time.Second)
		if err != nil {
			return CheckWarning, "TCP sink at 127.0.0.1:51888 not reachable", "Check that Fluent Bit is running"
		}
		conn.Close()
		return CheckPassed, "TCP sink at 127.0.0.1:51888 reachable", ""
	})

	// ---- Apt integration ----
	// On Debian/Ubuntu systems, verify the APT post-invoke hook is installed
	// so that package changes automatically trigger a rebaseline.
	r.check("Apt", "Apt hook installed", func() (CheckStatus, string, string) {
		if _, err := exec.LookPath("dpkg"); err != nil {
			// Not a Debian system — skip this check entirely.
			return CheckPassed, "dpkg not found (non-Debian system), skipping", ""
		}
		if _, err := os.Stat(AptHookPath); err != nil {
			return CheckWarning, "Apt hook not installed", "Run: trapline install"
		}
		return CheckPassed, "Apt hook at " + AptHookPath, ""
	})

	// Tally the final pass/warning/error counts from all collected checks.
	for _, c := range r.Checks {
		switch c.Status {
		case CheckPassed:
			r.Passed++
		case CheckWarning:
			r.Warnings++
		case CheckError:
			r.Errors++
		}
	}

	return r
}

// check is a helper that executes a single health-check function and appends
// the result to the DoctorResult's Checks slice. The fn callback returns the
// check status, a detail string describing what was found, and an optional
// fix string with remediation instructions.
func (r *DoctorResult) check(category, name string, fn func() (CheckStatus, string, string)) {
	status, detail, fix := fn()
	r.Checks = append(r.Checks, Check{
		Category: category,
		Name:     name,
		Status:   status,
		Detail:   detail,
		Fix:      fix,
	})
}

// Print outputs the doctor results to stdout in a human-readable format. Checks
// are grouped by category with a blank line between groups. Each check is
// displayed with its Unicode status indicator (checkmark/warning/cross) and
// detail string. If a fix is available, it is printed indented below the check.
// The final line shows a summary tally of passed, warnings, and errors.
func (r *DoctorResult) Print() {
	fmt.Println("Trapline Doctor — checking installation health...")
	fmt.Println()

	// Track the current category to insert section breaks between groups.
	currentCategory := ""
	for _, c := range r.Checks {
		if c.Category != currentCategory {
			if currentCategory != "" {
				fmt.Println() // blank line between categories
			}
			fmt.Println(c.Category)
			currentCategory = c.Category
		}
		fmt.Printf("  %s %s\n", c.Status, c.Detail)
		if c.Fix != "" {
			fmt.Printf("    Fix: %s\n", c.Fix)
		}
	}

	fmt.Printf("\nSummary: %d passed, %d warnings, %d errors\n", r.Passed, r.Warnings, r.Errors)
}
