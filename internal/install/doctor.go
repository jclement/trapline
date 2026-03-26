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

// DoctorResult holds the results of a health check.
type DoctorResult struct {
	Checks   []Check
	Passed   int
	Warnings int
	Errors   int
}

// Check represents a single doctor check.
type Check struct {
	Category string
	Name     string
	Status   CheckStatus
	Detail   string
	Fix      string
}

type CheckStatus int

const (
	CheckPassed CheckStatus = iota
	CheckWarning
	CheckError
)

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

// Doctor runs all health checks.
func Doctor() *DoctorResult {
	r := &DoctorResult{}

	// Binary & Installation
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

	// Configuration
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
		if mode&0044 != 0 {
			return CheckWarning, fmt.Sprintf("Config is readable by non-root (%04o)", mode), fmt.Sprintf("Run: chmod 600 %s", ConfigPath)
		}
		return CheckPassed, fmt.Sprintf("Config permissions %04o", mode), ""
	})

	// Systemd
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

	// Directories
	for _, dir := range []string{ConfigDir, StateDir, BaselinesDir, LogDir} {
		dirCopy := dir
		r.check("Directories", dirCopy+" exists", func() (CheckStatus, string, string) {
			info, err := os.Stat(dirCopy)
			if err != nil {
				return CheckError, dirCopy + " not found", "Run: trapline install"
			}
			return CheckPassed, fmt.Sprintf("%s exists (%04o)", dirCopy, info.Mode().Perm()), ""
		})
	}

	// Baselines
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
		if !oldest.IsZero() && time.Since(oldest) > 7*24*time.Hour {
			return CheckWarning, detail + " (oldest > 7 days)", "Consider: trapline rebaseline"
		}
		return CheckPassed, detail, ""
	})

	// Output sinks
	r.check("Output", "TCP sink reachable", func() (CheckStatus, string, string) {
		// Try default TCP address
		conn, err := net.DialTimeout("tcp", "127.0.0.1:51888", 2*time.Second)
		if err != nil {
			return CheckWarning, "TCP sink at 127.0.0.1:51888 not reachable", "Check that Fluent Bit is running"
		}
		conn.Close()
		return CheckPassed, "TCP sink at 127.0.0.1:51888 reachable", ""
	})

	// Apt integration
	r.check("Apt", "Apt hook installed", func() (CheckStatus, string, string) {
		if _, err := exec.LookPath("dpkg"); err != nil {
			return CheckPassed, "dpkg not found (non-Debian system), skipping", ""
		}
		if _, err := os.Stat(AptHookPath); err != nil {
			return CheckWarning, "Apt hook not installed", "Run: trapline install"
		}
		return CheckPassed, "Apt hook at " + AptHookPath, ""
	})

	// Tally
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

// Print outputs the doctor results to stdout.
func (r *DoctorResult) Print() {
	fmt.Println("Trapline Doctor — checking installation health...")
	fmt.Println()

	currentCategory := ""
	for _, c := range r.Checks {
		if c.Category != currentCategory {
			if currentCategory != "" {
				fmt.Println()
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
