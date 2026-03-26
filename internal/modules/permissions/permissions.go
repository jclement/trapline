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

// dirCache tracks directory mtimes to skip unchanged subtrees.
type dirCache struct {
	DirMtimes map[string]time.Time `json:"dir_mtimes"`
	LastFull  time.Time            `json:"last_full"`
}

type Module struct {
	store     *baseline.Store
	scanPaths []string
	cache     dirCache
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
	m.cache.DirMtimes = make(map[string]time.Time)
	m.store.Load(m.Name(), &m.cache)
	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	// Full walk every 6 hours; between full walks, only check dirs with changed mtimes.
	// This reduces I/O from tens of thousands of stat calls to a few hundred.
	fullScan := time.Since(m.cache.LastFull) > 6*time.Hour || len(m.cache.DirMtimes) == 0

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
				if !fullScan {
					// Skip directories whose mtime hasn't changed
					if cached, ok := m.cache.DirMtimes[path]; ok {
						if info.ModTime().Equal(cached) {
							return filepath.SkipDir
						}
					}
				}
				// Track this directory's mtime
				m.cache.DirMtimes[path] = info.ModTime()
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

	// Check shadow file permissions (always — single stat, negligible cost)
	if info, err := os.Stat("/etc/shadow"); err == nil {
		mode := info.Mode()
		if mode&0044 != 0 {
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

	// Check /usr/local/bin ownership (always — small directory)
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

	if fullScan {
		m.cache.LastFull = time.Now()
	}
	m.store.Save(m.Name(), m.cache)

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	// Reset cache to force a full walk on next scan
	m.cache.DirMtimes = make(map[string]time.Time)
	m.cache.LastFull = time.Time{}
	return m.store.Save(m.Name(), m.cache)
}
