package fileintegrity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type FileEntry struct {
	Hash  string      `json:"hash"`
	Mode  os.FileMode `json:"mode"`
	Owner uint32      `json:"owner"`
	Group uint32      `json:"group"`
	MTime time.Time   `json:"mtime"`
}

type Module struct {
	store     *baseline.Store
	baseline  map[string]FileEntry
	watchList []string
}

func New() *Module {
	return &Module{}
}

func (m *Module) Name() string { return "file-integrity" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store

	// Default watch list
	m.watchList = []string{
		"/etc/ssh/sshd_config",
		"/etc/passwd",
		"/etc/shadow",
		"/etc/group",
		"/etc/gshadow",
		"/etc/sudoers",
		"/etc/crontab",
		"/etc/docker/daemon.json",
	}

	// Add extra watch paths from config
	if extra, ok := cfg.Settings["watch_extra"]; ok {
		if paths, ok := extra.([]interface{}); ok {
			for _, p := range paths {
				if s, ok := p.(string); ok {
					m.watchList = append(m.watchList, s)
				}
			}
		}
	}

	// Load existing baseline
	m.baseline = make(map[string]FileEntry)
	m.store.Load(m.Name(), &m.baseline)

	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current := make(map[string]FileEntry)
	var findings []finding.Finding

	// Expand globs and scan files
	for _, pattern := range m.watchList {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if matches == nil {
			// Not a glob, treat as literal path
			matches = []string{pattern}
		}
		for _, path := range matches {
			entry, err := scanFile(path)
			if err != nil {
				continue // file may not exist
			}
			current[path] = entry
		}
	}

	// No baseline yet = learning mode
	if len(m.baseline) == 0 {
		m.baseline = current
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	// Check for modified and permission-changed files
	for path, cur := range current {
		if base, ok := m.baseline[path]; ok {
			if cur.Hash != base.Hash {
				sev := finding.SeverityMedium
				if isSensitivePath(path) {
					sev = finding.SeverityHigh
				}
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "file-modified:" + path,
					Severity:  sev,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("%s modified outside of package manager", filepath.Base(path)),
					Detail: map[string]interface{}{
						"path":          path,
						"baseline_hash": base.Hash,
						"current_hash":  cur.Hash,
						"mode":          fmt.Sprintf("%04o", cur.Mode),
						"mtime":         cur.MTime.Format(time.RFC3339),
					},
				})
			}
			if cur.Mode != base.Mode || cur.Owner != base.Owner || cur.Group != base.Group {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "file-permission-changed:" + path,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("%s permissions changed", filepath.Base(path)),
					Detail: map[string]interface{}{
						"path":           path,
						"baseline_mode":  fmt.Sprintf("%04o", base.Mode),
						"current_mode":   fmt.Sprintf("%04o", cur.Mode),
						"baseline_owner": base.Owner,
						"current_owner":  cur.Owner,
					},
				})
			}
		} else {
			// New file
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "file-added:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new file detected: %s", path),
				Detail: map[string]interface{}{
					"path": path,
					"hash": cur.Hash,
					"mode": fmt.Sprintf("%04o", cur.Mode),
				},
			})
		}
	}

	// Check for removed files
	for path := range m.baseline {
		if _, ok := current[path]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "file-removed:" + path,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("monitored file removed: %s", path),
				Detail:    map[string]interface{}{"path": path},
			})
		}
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	current := make(map[string]FileEntry)
	for _, pattern := range m.watchList {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if matches == nil {
			matches = []string{pattern}
		}
		for _, path := range matches {
			entry, err := scanFile(path)
			if err != nil {
				continue
			}
			current[path] = entry
		}
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

func scanFile(path string) (FileEntry, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return FileEntry{}, err
	}

	// Don't follow symlinks for hash, just track them
	if info.Mode()&os.ModeSymlink != 0 {
		return FileEntry{
			Mode:  info.Mode(),
			MTime: info.ModTime(),
		}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return FileEntry{
			Mode:  info.Mode(),
			MTime: info.ModTime(),
		}, nil
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return FileEntry{}, err
	}

	var owner, group uint32
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		owner = stat.Uid
		group = stat.Gid
	}

	return FileEntry{
		Hash:  hex.EncodeToString(h.Sum(nil)),
		Mode:  info.Mode(),
		Owner: owner,
		Group: group,
		MTime: info.ModTime(),
	}, nil
}

func isSensitivePath(path string) bool {
	sensitive := []string{
		"/etc/shadow", "/etc/gshadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/passwd",
	}
	for _, s := range sensitive {
		if path == s {
			return true
		}
	}
	return false
}
