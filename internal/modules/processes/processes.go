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

type ProcessEntry struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
	UID     int    `json:"uid"`
}

type DenyEntry struct {
	Name      string `json:"name"`
	MinUptime int    `json:"min_uptime,omitempty"`
}

type Module struct {
	store    *baseline.Store
	baseline []ProcessEntry
	deny     []DenyEntry
	// For testing
	ProcDir string
}

func New() *Module {
	return &Module{
		ProcDir: "/proc",
	}
}

func (m *Module) Name() string { return "processes" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.store.Load(m.Name(), &m.baseline)

	// Parse deny list from config
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

	// Default deny list
	if len(m.deny) == 0 {
		m.deny = []DenyEntry{
			{Name: "xmrig"},
			{Name: "cryptominer"},
		}
	}

	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.scanProcesses()
	if err != nil {
		return nil, err
	}

	var findings []finding.Finding

	// Check deny list
	for _, proc := range current {
		for _, deny := range m.deny {
			if strings.Contains(strings.ToLower(proc.Name), strings.ToLower(deny.Name)) {
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

	// Learning mode
	if len(m.baseline) == 0 {
		m.baseline = current
		m.store.Save(m.Name(), m.baseline)
		return findings, nil // still return deny findings
	}

	// Check for unexpected processes
	baseNames := make(map[string]bool)
	for _, p := range m.baseline {
		baseNames[p.Name] = true
	}

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

	// Check for missing expected processes
	curNames := make(map[string]bool)
	for _, p := range current {
		curNames[p.Name] = true
	}
	for _, base := range m.baseline {
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

func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.scanProcesses()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

func (m *Module) scanProcesses() ([]ProcessEntry, error) {
	entries, err := os.ReadDir(m.ProcDir)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var procs []ProcessEntry

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // not a PID directory
		}

		proc, err := readProcess(m.ProcDir, pid)
		if err != nil {
			continue
		}

		// Deduplicate by name (we care about unique process names, not PIDs)
		if seen[proc.Name] {
			continue
		}
		seen[proc.Name] = true
		procs = append(procs, proc)
	}

	return procs, nil
}

func readProcess(procDir string, pid int) (ProcessEntry, error) {
	pidDir := filepath.Join(procDir, strconv.Itoa(pid))

	// Read comm (process name)
	comm, err := os.ReadFile(filepath.Join(pidDir, "comm"))
	if err != nil {
		return ProcessEntry{}, err
	}

	// Read cmdline
	cmdline, _ := os.ReadFile(filepath.Join(pidDir, "cmdline"))

	// Read status for UID
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
