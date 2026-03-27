package processes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
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

func createFakeProc(t *testing.T, dir string, pid int, name string) {
	t.Helper()
	pidDir := filepath.Join(dir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte(name+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("/usr/bin/"+name+"\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\t"+name+"\nUid:\t0\t0\t0\t0\n"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestName(t *testing.T) {
	if New().Name() != "processes" {
		t.Error("wrong name")
	}
}

func TestScanLearningMode(t *testing.T) {
	cfg := testModuleConfig(t)
	procDir := t.TempDir()
	createFakeProc(t, procDir, 1, "init")
	createFakeProc(t, procDir, 100, "sshd")

	m := New()
	m.ProcDir = procDir
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}
}

func TestDetectsUnexpectedProcess(t *testing.T) {
	cfg := testModuleConfig(t)
	procDir := t.TempDir()
	createFakeProc(t, procDir, 1, "init")
	createFakeProc(t, procDir, 100, "sshd")

	m := New()
	m.ProcDir = procDir
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background()) // baseline

	// Add unexpected process
	createFakeProc(t, procDir, 666, "cryptominer")

	findings, _ := m.Scan(context.Background())
	foundDenied := false
	foundUnexpected := false
	for _, f := range findings {
		if f.FindingID == "process-denied:cryptominer:666" {
			foundDenied = true
		}
		if f.FindingID == "process-unexpected:cryptominer" {
			foundUnexpected = true
		}
	}
	if !foundDenied {
		t.Error("expected process-denied finding for cryptominer")
	}
	if !foundUnexpected {
		t.Error("expected process-unexpected finding for cryptominer")
	}
}

func TestDetectsMissingProcess(t *testing.T) {
	cfg := testModuleConfig(t)
	procDir := t.TempDir()
	createFakeProc(t, procDir, 1, "init")
	createFakeProc(t, procDir, 100, "sshd")

	m := New()
	m.ProcDir = procDir
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background()) // baseline

	// Remove sshd
	if err := os.RemoveAll(filepath.Join(procDir, "100")); err != nil {
		t.Fatal(err)
	}

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "process-missing:sshd" {
			found = true
		}
	}
	if !found {
		t.Error("expected process-missing finding for sshd")
	}
}

func TestDenyList(t *testing.T) {
	cfg := testModuleConfig(t)
	procDir := t.TempDir()
	createFakeProc(t, procDir, 1, "init")
	createFakeProc(t, procDir, 999, "xmrig")

	m := New()
	m.ProcDir = procDir
	_ = m.Init(cfg)

	// Even in learning mode, deny list should fire
	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if strings.Contains(f.FindingID, "process-denied") && strings.Contains(f.FindingID, "xmrig") {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected critical severity for denied process")
			}
		}
	}
	if !found {
		t.Error("expected process-denied finding for xmrig")
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	procDir := t.TempDir()
	createFakeProc(t, procDir, 1, "init")

	m := New()
	m.ProcDir = procDir
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background()) // baseline

	createFakeProc(t, procDir, 200, "newproc")
	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatal(err)
	}

	findings, _ := m.Scan(context.Background())
	// Filter out deny-list findings
	unexpected := 0
	for _, f := range findings {
		if strings.Contains(f.FindingID, "process-unexpected") {
			unexpected++
		}
	}
	if unexpected != 0 {
		t.Errorf("expected 0 unexpected after rebaseline, got %d", unexpected)
	}
}
