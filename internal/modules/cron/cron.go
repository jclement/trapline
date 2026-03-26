package cron

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type CronEntry struct {
	Source string `json:"source"`
	Line   string `json:"line"`
	Hash   string `json:"hash"`
}

type Module struct {
	store          *baseline.Store
	baseline       []CronEntry
	baselineLoaded bool
	// For testing
	CronDirs    []string
	CrontabPath string
}

func New() *Module {
	return &Module{
		CrontabPath: "/etc/crontab",
		CronDirs: []string{
			"/etc/cron.d",
			"/etc/cron.hourly",
			"/etc/cron.daily",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
			"/var/spool/cron/crontabs",
		},
	}
}

func (m *Module) Name() string { return "cron" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)
	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current := m.scanCrons()

	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding
	baseMap := cronToMap(m.baseline)
	curMap := cronToMap(current)

	for key, cur := range curMap {
		if base, ok := baseMap[key]; ok {
			if cur.Hash != base.Hash {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "cron-modified:" + cur.Source,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("cron job modified in %s", cur.Source),
					Detail:    map[string]interface{}{"source": cur.Source, "line": cur.Line},
				})
			}
		} else {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "cron-added:" + cur.Source,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new cron job detected in %s", cur.Source),
				Detail:    map[string]interface{}{"source": cur.Source, "line": cur.Line},
			})
		}
	}

	for key, base := range baseMap {
		if _, ok := curMap[key]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "cron-removed:" + base.Source,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("cron job removed from %s", base.Source),
				Detail:    map[string]interface{}{"source": base.Source},
			})
		}
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	m.baseline = m.scanCrons()
	return m.store.Save(m.Name(), m.baseline)
}

func (m *Module) scanCrons() []CronEntry {
	var entries []CronEntry

	// Scan main crontab
	if e := scanCronFile(m.CrontabPath); len(e) > 0 {
		entries = append(entries, e...)
	}

	// Scan cron directories
	for _, dir := range m.CronDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			continue
		}
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil || info.IsDir() {
				continue
			}
			if e := scanCronFile(f); len(e) > 0 {
				entries = append(entries, e...)
			}
		}
	}

	return entries
}

func scanCronFile(path string) []CronEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var entries []CronEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip variable assignments (SHELL=, PATH=, etc.)
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(line)))
		entries = append(entries, CronEntry{
			Source: path,
			Line:   line,
			Hash:   hash[:16],
		})
	}

	return entries
}

func cronToMap(entries []CronEntry) map[string]CronEntry {
	m := make(map[string]CronEntry)
	for _, e := range entries {
		key := e.Source + ":" + e.Hash
		m[key] = e
	}
	return m
}
