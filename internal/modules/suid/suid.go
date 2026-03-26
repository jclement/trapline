package suid

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type SuidEntry struct {
	Path string      `json:"path"`
	Mode os.FileMode `json:"mode"`
}

type SuidBaseline struct {
	Initialized bool                  `json:"initialized"`
	Entries     map[string]SuidEntry  `json:"entries"`
}

type Module struct {
	store        *baseline.Store
	baseline     SuidBaseline
	scanPaths    []string
	excludePaths []string
}

func New() *Module {
	return &Module{
		scanPaths:    []string{"/usr", "/bin", "/sbin", "/opt"},
		excludePaths: []string{"/proc", "/sys", "/dev", "/var/lib/docker", "/snap"},
	}
}

func (m *Module) Name() string { return "suid" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baseline = SuidBaseline{Entries: make(map[string]SuidEntry)}
	m.store.Load(m.Name(), &m.baseline)
	if m.baseline.Entries == nil {
		m.baseline.Entries = make(map[string]SuidEntry)
	}

	if paths, ok := cfg.Settings["scan_paths"]; ok {
		if ps, ok := paths.([]interface{}); ok {
			m.scanPaths = nil
			for _, p := range ps {
				if s, ok := p.(string); ok {
					m.scanPaths = append(m.scanPaths, s)
				}
			}
		}
	}

	if paths, ok := cfg.Settings["exclude_paths"]; ok {
		if ps, ok := paths.([]interface{}); ok {
			m.excludePaths = nil
			for _, p := range ps {
				if s, ok := p.(string); ok {
					m.excludePaths = append(m.excludePaths, s)
				}
			}
		}
	}

	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current := m.findSuidBinaries(ctx)

	if !m.baseline.Initialized {
		m.baseline = SuidBaseline{Initialized: true, Entries: current}
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding

	for path, entry := range current {
		if _, ok := m.baseline.Entries[path]; !ok {
			sev := finding.SeverityHigh
			// SUID in /tmp is critical
			if filepath.HasPrefix(path, "/tmp") || filepath.HasPrefix(path, "/var/tmp") {
				sev = finding.SeverityCritical
			}
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "suid-unexpected:" + path,
				Severity:  sev,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("unexpected SUID/SGID binary: %s", path),
				Detail: map[string]interface{}{
					"path": path,
					"mode": fmt.Sprintf("%04o", entry.Mode),
				},
			})
		}
	}

	for path := range m.baseline.Entries {
		if _, ok := current[path]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "suid-removed:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("SUID/SGID binary removed: %s", path),
				Detail:    map[string]interface{}{"path": path},
			})
		}
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	m.baseline = SuidBaseline{Initialized: true, Entries: m.findSuidBinaries(ctx)}
	return m.store.Save(m.Name(), m.baseline)
}

func (m *Module) findSuidBinaries(ctx context.Context) map[string]SuidEntry {
	result := make(map[string]SuidEntry)

	for _, root := range m.scanPaths {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if err != nil {
				return nil
			}

			// Check exclusions
			for _, excl := range m.excludePaths {
				if filepath.HasPrefix(path, excl) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}

			if info.IsDir() {
				return nil
			}

			mode := info.Mode()
			if mode&os.ModeSetuid != 0 || mode&os.ModeSetgid != 0 {
				result[path] = SuidEntry{Path: path, Mode: mode}
			}

			return nil
		})
	}

	return result
}
