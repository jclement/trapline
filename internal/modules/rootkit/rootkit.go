package rootkit

import (
	"bufio"
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

// knownHiddenFiles are dotfiles commonly found in tmp dirs that are not suspicious.
var knownHiddenFiles = map[string]bool{
	".X11-unix":  true,
	".ICE-unix":  true,
	".font-unix": true,
	".XIM-unix":  true,
}

// Module implements rootkit detection checks.
type Module struct {
	store *baseline.Store

	// Configurable filesystem paths for testing.
	ProcDir string
	SysDir  string
	TmpDirs []string
	DevDir  string
}

// New creates a new rootkit detection module.
func New() *Module {
	return &Module{
		ProcDir: "/proc",
		SysDir:  "/sys",
		TmpDirs: []string{"/tmp", "/var/tmp", "/dev/shm"},
		DevDir:  "/dev",
	}
}

func (m *Module) Name() string { return "rootkit" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	return nil
}

// kernelBaseline is the structure persisted for kernel module baselining.
type kernelBaseline struct {
	Modules map[string]bool `json:"modules"`
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	// 1. Kernel modules check
	kf, err := m.checkKernelModules()
	if err == nil {
		findings = append(findings, kf...)
	}

	// 2. Hidden files in tmp dirs
	hf := m.checkHiddenFiles()
	findings = append(findings, hf...)

	// 3. Regular files in /dev
	df := m.checkDevFiles()
	findings = append(findings, df...)

	// 4. Promiscuous interfaces
	pf := m.checkPromiscuous()
	findings = append(findings, pf...)

	// 5. Deleted exe processes
	ef := m.checkDeletedExe()
	findings = append(findings, ef...)

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	modules, err := m.readKernelModules()
	if err != nil {
		return err
	}
	bl := kernelBaseline{Modules: modules}
	return m.store.Save(m.Name(), &bl)
}

// checkKernelModules reads /proc/modules and compares against baseline.
func (m *Module) checkKernelModules() ([]finding.Finding, error) {
	current, err := m.readKernelModules()
	if err != nil {
		return nil, err
	}

	var bl kernelBaseline
	exists, err := m.store.Load(m.Name(), &bl)
	if err != nil {
		return nil, err
	}

	if !exists {
		// Learning mode: save baseline, return no findings.
		bl = kernelBaseline{Modules: current}
		if err := m.store.Save(m.Name(), &bl); err != nil {
			return nil, err
		}
		return nil, nil
	}

	var findings []finding.Finding
	for mod := range current {
		if !bl.Modules[mod] {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "new-kernel-module:" + mod,
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new kernel module loaded: %s", mod),
				Detail: map[string]interface{}{
					"module": mod,
				},
			})
		}
	}

	return findings, nil
}

// readKernelModules parses /proc/modules and returns a set of module names.
func (m *Module) readKernelModules() (map[string]bool, error) {
	path := filepath.Join(m.ProcDir, "modules")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	modules := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules[fields[0]] = true
		}
	}
	return modules, scanner.Err()
}

// checkHiddenFiles scans tmp dirs for suspicious dotfiles.
func (m *Module) checkHiddenFiles() []finding.Finding {
	var findings []finding.Finding
	for _, dir := range m.TmpDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, ".") {
				continue
			}
			if name == "." || name == ".." {
				continue
			}
			if knownHiddenFiles[name] {
				continue
			}
			fullPath := filepath.Join(dir, name)
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "hidden-file:" + fullPath,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("hidden file in %s: %s", dir, name),
				Detail: map[string]interface{}{
					"path": fullPath,
					"dir":  dir,
				},
			})
		}
	}
	return findings
}

// checkDevFiles looks for regular files in /dev.
func (m *Module) checkDevFiles() []finding.Finding {
	var findings []finding.Finding
	entries, err := os.ReadDir(m.DevDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		// Only flag regular files (not dirs, symlinks, or device files).
		if !entry.Type().IsRegular() {
			continue
		}
		fullPath := filepath.Join(m.DevDir, entry.Name())
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "dev-regular-file:" + fullPath,
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("regular file in /dev: %s", entry.Name()),
			Detail: map[string]interface{}{
				"path": fullPath,
			},
		})
	}
	return findings
}

// checkPromiscuous reads network interface flags and checks for IFF_PROMISC (0x100).
func (m *Module) checkPromiscuous() []finding.Finding {
	var findings []finding.Finding
	netDir := filepath.Join(m.SysDir, "class", "net")
	ifaces, err := os.ReadDir(netDir)
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		flagsPath := filepath.Join(netDir, iface.Name(), "flags")
		data, err := os.ReadFile(flagsPath)
		if err != nil {
			continue
		}
		flagStr := strings.TrimSpace(string(data))
		flags, err := strconv.ParseUint(strings.TrimPrefix(flagStr, "0x"), 16, 64)
		if err != nil {
			continue
		}
		if flags&0x100 != 0 {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "promiscuous-interface:" + iface.Name(),
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("network interface %s is in promiscuous mode", iface.Name()),
				Detail: map[string]interface{}{
					"interface": iface.Name(),
					"flags":     flagStr,
				},
			})
		}
	}
	return findings
}

// checkDeletedExe looks for processes whose binary has been deleted.
func (m *Module) checkDeletedExe() []finding.Finding {
	var findings []finding.Finding
	entries, err := os.ReadDir(m.ProcDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Only look at numeric (PID) directories.
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		exePath := filepath.Join(m.ProcDir, entry.Name(), "exe")
		target, err := os.Readlink(exePath)
		if err != nil {
			continue
		}
		if strings.HasSuffix(target, " (deleted)") {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "deleted-exe:" + entry.Name(),
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("process %s running with deleted binary", entry.Name()),
				Detail: map[string]interface{}{
					"pid":  entry.Name(),
					"exe":  target,
				},
			})
		}
	}
	return findings
}
