package rootkit

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jclement/tripline/internal/engine"
)

func initModule(t *testing.T) (*Module, string) {
	t.Helper()
	tmp := t.TempDir()
	m := New()
	m.ProcDir = filepath.Join(tmp, "proc")
	m.SysDir = filepath.Join(tmp, "sys")
	m.TmpDirs = []string{filepath.Join(tmp, "tmp1")}
	m.DevDir = filepath.Join(tmp, "dev")

	if err := os.MkdirAll(m.ProcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.SysDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.TmpDirs[0], 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.DevDir, 0755); err != nil {
		t.Fatal(err)
	}

	baselinesDir := filepath.Join(tmp, "baselines")
	cfg := engine.ModuleConfig{
		Settings:     map[string]interface{}{},
		StateDir:     tmp,
		BaselinesDir: baselinesDir,
	}
	if err := m.Init(cfg); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	return m, tmp
}

func TestName(t *testing.T) {
	m := New()
	if m.Name() != "rootkit" {
		t.Fatalf("expected name 'rootkit', got %q", m.Name())
	}
}

func TestKernelModulesLearningMode(t *testing.T) {
	m, _ := initModule(t)

	writeFile(t, filepath.Join(m.ProcDir, "modules"),
		"ext4 589824 1 - Live 0xffffffffa0000000\nnfsd 409600 13 - Live 0xffffffffa0100000\n")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in learning mode, got %d", len(findings))
	}
}

func TestDetectsNewKernelModule(t *testing.T) {
	m, _ := initModule(t)

	// First scan: baseline
	writeFile(t, filepath.Join(m.ProcDir, "modules"),
		"ext4 589824 1 - Live 0xffffffffa0000000\nnfsd 409600 13 - Live 0xffffffffa0100000\n")

	_, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("first scan error: %v", err)
	}

	// Second scan: new module appears
	writeFile(t, filepath.Join(m.ProcDir, "modules"),
		"ext4 589824 1 - Live 0xffffffffa0000000\nnfsd 409600 13 - Live 0xffffffffa0100000\nevil_rootkit 12345 0 - Live 0xffffffffa0200000\n")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("second scan error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "new-kernel-module:evil_rootkit" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected finding for new kernel module 'evil_rootkit'")
	}
}

func TestDetectsHiddenFiles(t *testing.T) {
	m, _ := initModule(t)

	writeFile(t, filepath.Join(m.TmpDirs[0], ".malware"), "bad stuff")
	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "hidden-file:"+filepath.Join(m.TmpDirs[0], ".malware") {
			found = true
			if f.Severity != "medium" {
				t.Errorf("expected severity medium, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected finding for hidden file .malware")
	}
}

func TestIgnoresKnownHiddenFiles(t *testing.T) {
	m, _ := initModule(t)

	if err := os.MkdirAll(filepath.Join(m.TmpDirs[0], ".X11-unix"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.TmpDirs[0], ".ICE-unix"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.TmpDirs[0], ".font-unix"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.TmpDirs[0], ".XIM-unix"), 0755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range findings {
		for known := range knownHiddenFiles {
			if f.FindingID == "hidden-file:"+filepath.Join(m.TmpDirs[0], known) {
				t.Fatalf("should not have flagged known-good hidden file %s", known)
			}
		}
	}
}

func TestDetectsFilesInDev(t *testing.T) {
	m, _ := initModule(t)

	writeFile(t, filepath.Join(m.DevDir, "suspicious_file"), "rootkit payload")
	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "dev-regular-file:"+filepath.Join(m.DevDir, "suspicious_file") {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity high, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected finding for regular file in /dev")
	}
}

func TestIgnoresDeviceFiles(t *testing.T) {
	m, _ := initModule(t)

	if err := os.Symlink("/dev/null", filepath.Join(m.DevDir, "link_to_null")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.DevDir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range findings {
		if f.FindingID == "dev-regular-file:"+filepath.Join(m.DevDir, "link_to_null") {
			t.Fatal("should not flag symlinks in /dev")
		}
		if f.FindingID == "dev-regular-file:"+filepath.Join(m.DevDir, "subdir") {
			t.Fatal("should not flag directories in /dev")
		}
	}
}

func TestDetectsDeletedExe(t *testing.T) {
	m, _ := initModule(t)

	pidDir := filepath.Join(m.ProcDir, "1234")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/something (deleted)", filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "deleted-exe:1234" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected finding for deleted exe process")
	}
}

func TestPromiscuousInterface(t *testing.T) {
	m, _ := initModule(t)

	ethDir := filepath.Join(m.SysDir, "class", "net", "eth0")
	if err := os.MkdirAll(ethDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(ethDir, "flags"), "0x1103")

	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "promiscuous-interface:eth0" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected severity critical, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected finding for promiscuous interface")
	}
}

func TestNormalInterface(t *testing.T) {
	m, _ := initModule(t)

	ethDir := filepath.Join(m.SysDir, "class", "net", "eth0")
	if err := os.MkdirAll(ethDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(ethDir, "flags"), "0x1003")

	writeFile(t, filepath.Join(m.ProcDir, "modules"), "")

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range findings {
		if f.FindingID == "promiscuous-interface:eth0" {
			t.Fatal("should not flag non-promiscuous interface")
		}
	}
}

func TestRebaseline(t *testing.T) {
	m, _ := initModule(t)

	// First scan: baseline
	writeFile(t, filepath.Join(m.ProcDir, "modules"),
		"ext4 589824 1 - Live 0xffffffffa0000000\n")

	_, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("first scan error: %v", err)
	}

	// Add new module
	writeFile(t, filepath.Join(m.ProcDir, "modules"),
		"ext4 589824 1 - Live 0xffffffffa0000000\nnew_mod 12345 0 - Live 0xffffffffa0200000\n")

	// Rebaseline
	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatalf("Rebaseline error: %v", err)
	}

	// Scan should no longer flag new_mod
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("scan after rebaseline error: %v", err)
	}

	for _, f := range findings {
		if f.FindingID == "new-kernel-module:new_mod" {
			t.Fatal("new_mod should not be flagged after rebaseline")
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
