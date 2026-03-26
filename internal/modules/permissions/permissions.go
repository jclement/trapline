package permissions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type Module struct {
	store     *baseline.Store
	scanPaths []string
}

func New() *Module {
	return &Module{
		scanPaths: []string{"/etc", "/usr", "/var"},
	}
}

func (m *Module) Name() string { return "permissions" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	// Check for world-writable files in sensitive dirs
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
			if info.IsDir() {
				return nil
			}

			mode := info.Mode()
			if mode&0002 != 0 { // world-writable
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "perm-world-writable:" + path,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("world-writable file in sensitive location: %s", path),
					Detail: map[string]interface{}{
						"path": path,
						"mode": fmt.Sprintf("%04o", mode.Perm()),
					},
				})
			}

			return nil
		})
	}

	// Check shadow file permissions
	if info, err := os.Stat("/etc/shadow"); err == nil {
		mode := info.Mode()
		if mode&0044 != 0 { // readable by group or others
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "perm-shadow-readable",
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   "/etc/shadow is readable by non-root",
				Detail: map[string]interface{}{
					"mode": fmt.Sprintf("%04o", mode.Perm()),
				},
			})
		}
	}

	// Check /usr/local/bin ownership
	if entries, err := os.ReadDir("/usr/local/bin"); err == nil {
		for _, entry := range entries {
			path := filepath.Join("/usr/local/bin", entry.Name())
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if stat.Uid != 0 {
					findings = append(findings, finding.Finding{
						Timestamp: time.Now().UTC(),
						FindingID: "perm-bad-owner:" + path,
						Severity:  finding.SeverityMedium,
						Status:    finding.StatusNew,
						Summary:   fmt.Sprintf("%s not owned by root (uid=%d)", path, stat.Uid),
						Detail: map[string]interface{}{
							"path": path,
							"uid":  stat.Uid,
						},
					})
				}
			}
		}
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	// Permissions module is stateless - it checks absolute rules, not diffs
	return nil
}
