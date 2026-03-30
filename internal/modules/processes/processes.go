// Package processes implements a process monitoring scanner for Trapline.
//
// # What It Monitors and Why
//
// This module enumerates all running processes by reading /proc/<pid>/ entries
// and compares them against a known-good baseline and a deny list of known-bad
// process names. Process monitoring is critical because nearly every active
// intrusion involves running unauthorized processes -- cryptominers, reverse
// shells, C2 agents, credential harvesters, and lateral movement tools.
//
// # How It Works
//
// The module performs two independent checks on each scan:
//
//  1. Deny list check (always active, even during learning mode): Each running
//     process name is compared against a configurable list of known-bad names
//     using case-insensitive exact matching. Matches generate Critical severity
//     findings immediately. The deny list ships with defaults (xmrig, cryptominer)
//     and can be extended via configuration.
//
//  2. Baseline comparison (active after first scan): The set of unique process
//     names is compared to the baseline. New process names and missing expected
//     processes both generate findings. Processes are deduplicated by name --
//     we track which process names exist, not individual PIDs, because the
//     security question is "is this type of process supposed to be running?"
//     rather than "is this specific PID expected?"
//
// Data is collected by reading /proc/<pid>/comm (process name), /proc/<pid>/cmdline
// (full command line), and /proc/<pid>/status (UID) for each numeric directory
// in /proc.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - Execution (T1059): Reverse shells, script interpreters launched by attackers.
//   - Resource Hijacking (T1496): Cryptominers (xmrig, etc.) detected by deny list.
//   - Persistence (T1543): Unauthorized daemons or services running.
//   - Lateral Movement (T1021): Tools like psexec, chisel, or tunneling utilities.
//   - Defense Evasion (T1036): Process name changes detected via baseline comparison
//     (though the attacker can rename to match an expected process).
//   - Service disruption: Expected processes no longer running.
//
// # What It Does NOT Catch (Known Limitations)
//
//   - Process name masquerading (T1036): An attacker who names their process the
//     same as a legitimate one (e.g., "sshd") will not be detected by the baseline
//     comparison since we deduplicate by name.
//   - Short-lived processes: A process that spawns and exits between scan intervals
//     will never be observed. Use auditd or eBPF for comprehensive process
//     accounting.
//   - Kernel threads and rootkit-hidden processes: If a rootkit hides /proc entries,
//     we cannot see the process.
//   - In-memory-only execution: Code injected into an existing process (e.g., via
//     ptrace) will not appear as a new process.
//   - The deny list uses exact name matching only. Attackers who rename their binary
//     (e.g., "xmr1g" instead of "xmrig") will bypass it.
//
// # False Positive Risks
//
//   - Legitimate new services started after baseline was established.
//   - Cron jobs and scheduled tasks that run intermittently will appear as
//     "unexpected" then "missing" across scans.
//   - System updates installing new daemons.
//   - Mitigation: Rebaseline after planned changes. Consider the scan interval --
//     short-lived legitimate processes can be filtered in the alert pipeline.
//
// # Performance Characteristics
//
//   - I/O: Three file reads per process (/proc/<pid>/comm, cmdline, status).
//     On a system with ~200 processes, this is ~600 small reads from the /proc
//     virtual filesystem (kernel memory, not disk I/O).
//   - CPU: Negligible. String comparisons and map lookups.
//   - Memory: Proportional to the number of unique process names (typically dozens
//     to low hundreds).
//   - No external process spawns. Reads /proc directly to avoid rootkit evasion
//     of userspace tools like ps.
//
// # Configuration Options
//
//   - deny ([]map[string]interface{}): List of denied process names. Each entry
//     has a "name" (string) and optional "min_uptime" (int, currently reserved).
//     If not configured, defaults to ["xmrig", "cryptominer"].
//   - exclude ([]string): List of glob patterns for process names to ignore.
//     Matched using filepath.Match. If not configured, defaults to ["kworker/*"]
//     to suppress noise from ephemeral kernel worker threads.
//   - ProcDir (string): Path to /proc, overridable for testing.
package processes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// ProcessEntry represents a single running process. The Name field comes from
// /proc/<pid>/comm (max 16 chars, kernel-truncated), Cmdline from
// /proc/<pid>/cmdline (full argv with NUL delimiters replaced by spaces),
// and UID from /proc/<pid>/status.
type ProcessEntry struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
	UID     int    `json:"uid"`
}

// DenyEntry defines a known-bad process name. MinUptime is reserved for future
// use to allow filtering out short-lived processes that might match by name
// but are legitimate (e.g., a monitoring tool briefly named "miner" in its cmdline).
type DenyEntry struct {
	Name      string `json:"name"`
	MinUptime int    `json:"min_uptime,omitempty"`
}

// Module is the process monitoring scanner. It maintains a baseline of expected
// process names and a deny list of known-bad process names. Deny list checks
// run even during learning mode to catch threats immediately.
type Module struct {
	store          *baseline.Store
	baseline       []ProcessEntry
	baselineLoaded bool
	deny           []DenyEntry
	exclude        []string
	// ProcDir is the path to /proc. Exported for testing so unit tests can
	// point at a fixture directory with synthetic /proc/<pid>/ entries.
	ProcDir string
}

// New creates a Module with the default /proc path. Call Init() before use.
func New() *Module {
	return &Module{
		ProcDir: "/proc",
	}
}

// Name returns the module identifier used for baseline storage and finding IDs.
func (m *Module) Name() string { return "processes" }

// Init sets up the baseline store, loads any persisted baseline, and configures
// the deny list. The deny list is loaded from config if present, otherwise
// defaults are used. Defaults target the most common cryptocurrency miners
// since cryptojacking is the #1 automated post-exploitation activity.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)

	// Parse deny list from config. The config value is a []interface{} because
	// it comes from JSON/YAML unmarshaling into generic types. Each entry is
	// a map with "name" and optionally "min_uptime".
	if denyRaw, ok := cfg.Settings["deny"]; ok {
		if denyList, ok := denyRaw.([]interface{}); ok {
			for _, d := range denyList {
				if dm, ok := d.(map[string]interface{}); ok {
					entry := DenyEntry{}
					if name, ok := dm["name"].(string); ok {
						entry.Name = name
					}
					if uptime, ok := dm["min_uptime"].(int); ok {
						entry.MinUptime = uptime
					}
					m.deny = append(m.deny, entry)
				}
			}
		}
	}

	// Default deny list: xmrig is the most common open-source cryptominer
	// found in compromised servers. "cryptominer" is a generic catch-all.
	if len(m.deny) == 0 {
		m.deny = []DenyEntry{
			{Name: "xmrig"},
			{Name: "cryptominer"},
		}
	}

	// Parse exclude list from config. Each entry is a glob pattern matched
	// against process names using filepath.Match. This filters out ephemeral
	// processes like kernel workers that churn constantly and produce noise.
	if exclRaw, ok := cfg.Settings["exclude"]; ok {
		if exclList, ok := exclRaw.([]interface{}); ok {
			for _, e := range exclList {
				if pattern, ok := e.(string); ok {
					m.exclude = append(m.exclude, pattern)
				}
			}
		}
	}

	// Default exclude list: kworker threads are ephemeral kernel workers
	// that constantly spawn and die, producing endless false positives.
	if len(m.exclude) == 0 {
		m.exclude = []string{"kworker/*"}
	}

	return nil
}

// isExcluded returns true if the process name matches any exclude pattern.
func (m *Module) isExcluded(name string) bool {
	for _, pattern := range m.exclude {
		if matched, _ := filepath.Match(pattern, name); matched {
			return true
		}
	}
	return false
}

// Scan enumerates running processes and produces findings for deny list matches,
// unexpected processes, and missing expected processes.
//
// Important: deny list findings are generated even during learning mode (before
// a baseline exists). This ensures that if the system is already compromised
// when Trapline first starts, known-bad processes are still flagged immediately.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.scanProcesses()
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding

	// Deny list check runs unconditionally (even before baseline is established).
	// Uses exact name matching (case-insensitive) rather than substring matching
	// to prevent false positives like "ssh" matching "openssh-keyscan" or
	// "mine" matching "prometheus-miner-exporter".
	for _, proc := range current {
		for _, deny := range m.deny {
			if strings.EqualFold(proc.Name, deny.Name) {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: fmt.Sprintf("process-denied:%s:%d", proc.Name, proc.PID),
					Severity:  finding.SeverityCritical,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("denied process '%s' running (PID %d)", proc.Name, proc.PID),
					Detail: map[string]interface{}{
						"pid":     proc.PID,
						"name":    proc.Name,
						"cmdline": proc.Cmdline,
						"uid":     proc.UID,
					},
				})
			}
		}
	}

	// Learning mode: record current processes as baseline but still return
	// any deny list findings from above. This is critical -- if an attacker
	// compromises the system before Trapline starts, we still want to catch
	// known-bad processes even though we have no baseline yet.
	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		_ = m.store.Save(m.Name(), m.baseline)
		return findings, nil
	}

	// Build a set of expected process names from the baseline for O(1) lookups.
	baseNames := make(map[string]bool)
	for _, p := range m.baseline {
		baseNames[p.Name] = true
	}

	// Detect unexpected processes: any process name not in the baseline.
	// This catches renamed malware, new backdoor services, attacker tools, etc.
	for _, proc := range current {
		if !baseNames[proc.Name] {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: fmt.Sprintf("process-unexpected:%s", proc.Name),
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("unexpected process '%s' running (PID %d)", proc.Name, proc.PID),
				Detail: map[string]interface{}{
					"pid":     proc.PID,
					"name":    proc.Name,
					"cmdline": proc.Cmdline,
				},
			})
		}
	}

	// Detect missing expected processes: baseline processes no longer running.
	// This can indicate an attacker killed a service (e.g., stopped logging),
	// or a service crash that needs attention.
	curNames := make(map[string]bool)
	for _, p := range current {
		curNames[p.Name] = true
	}
	for _, base := range m.baseline {
		if m.isExcluded(base.Name) {
			continue
		}
		if !curNames[base.Name] {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: fmt.Sprintf("process-missing:%s", base.Name),
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("expected process '%s' not running", base.Name),
				Detail: map[string]interface{}{
					"name": base.Name,
				},
			})
		}
	}

	return findings, nil
}

// Rebaseline captures the current set of running process names as the new
// baseline. Call this after planned service changes to prevent false positives.
func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.scanProcesses()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

// scanProcesses enumerates /proc and reads metadata for each process.
// It deduplicates by process name because the baseline comparison operates
// on "what types of processes are running" not "what specific PIDs exist."
// This means multiple instances of the same process (e.g., worker pools)
// are treated as a single entry, which is the correct security abstraction.
func (m *Module) scanProcesses() ([]ProcessEntry, error) {
	entries, err := os.ReadDir(m.ProcDir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var procs []ProcessEntry

	for _, entry := range entries {
		// Only numeric directory names are PID entries. Non-numeric entries
		// like "self", "net", "sys" are kernel pseudo-directories.
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		proc, err := readProcess(m.ProcDir, pid)
		if err != nil {
			// Process may have exited between readdir and read -- this is
			// normal and expected (TOCTOU race with /proc).
			continue
		}

		// Skip excluded processes before dedup and collection.
		if m.isExcluded(proc.Name) {
			continue
		}

		// Deduplicate by name: we care about unique process names, not PIDs.
		// This keeps the baseline stable across restarts of multi-instance
		// services (e.g., nginx workers get different PIDs but same name).
		if seen[proc.Name] {
			continue
		}
		seen[proc.Name] = true
		procs = append(procs, proc)
	}

	return procs, nil
}

// readProcess reads metadata for a single process from /proc/<pid>/.
// It reads three files:
//   - comm: the process name (kernel-truncated to 16 chars)
//   - cmdline: full command line with NUL-delimited argv
//   - status: parsed for the real UID (first field of the Uid: line)
func readProcess(procDir string, pid int) (ProcessEntry, error) {
	pidDir := filepath.Join(procDir, strconv.Itoa(pid))

	// Read comm (process name). This is the kernel's task name, limited to
	// 16 characters. It can be set by prctl(PR_SET_NAME) so an attacker
	// can change it, but it is the most reliable short name available.
	comm, err := os.ReadFile(filepath.Join(pidDir, "comm"))
	if err != nil {
		return ProcessEntry{}, err
	}

	// Read cmdline. This contains the full argv with NUL byte separators.
	// We replace NULs with spaces for human readability. Note: a process
	// can modify its own cmdline (visible in /proc), so this is informational
	// rather than authoritative.
	cmdline, _ := os.ReadFile(filepath.Join(pidDir, "cmdline"))

	// Read status file and extract the real UID. The Uid: line contains four
	// fields: real, effective, saved-set, and filesystem UIDs. We use the
	// real UID (fields[1], first after "Uid:") to identify who started the process.
	var uid int
	status, err := os.ReadFile(filepath.Join(pidDir, "status"))
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					uid, _ = strconv.Atoi(fields[1])
				}
				break
			}
		}
	}

	return ProcessEntry{
		PID:     pid,
		Name:    strings.TrimSpace(string(comm)),
		Cmdline: strings.ReplaceAll(string(cmdline), "\x00", " "),
		UID:     uid,
	}, nil
}
