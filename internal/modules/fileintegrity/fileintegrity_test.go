package fileintegrity

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
	m := New()
	if m.Name() != "file-integrity" {
		t.Errorf("Name() = %q", m.Name())
	}
}

func TestInitAndScanLearningMode(t *testing.T) {
	cfg := testModuleConfig(t)
	// Create a test file to watch
	testFile := filepath.Join(t.TempDir(), "testfile")
	os.WriteFile(testFile, []byte("hello"), 0644)

	cfg.Settings["watch_extra"] = []interface{}{testFile}

	m := New()
	m.watchList = []string{} // clear defaults
	if err := m.Init(cfg); err != nil {
		t.Fatalf("Init() error: %v", err)
	}
	m.watchList = []string{testFile}

	// First scan = learning mode, no findings
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}
}

func TestDetectsModifiedFile(t *testing.T) {
	cfg := testModuleConfig(t)
	testFile := filepath.Join(t.TempDir(), "watched")
	os.WriteFile(testFile, []byte("original"), 0644)

	m := New()
	m.Init(cfg)
	m.watchList = []string{testFile}

	// First scan - baseline
	m.Scan(context.Background())

	// Modify file
	os.WriteFile(testFile, []byte("modified"), 0644)

	// Second scan - should detect modification
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings for modified file")
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "file-modified:"+testFile {
			found = true
			if f.Summary == "" {
				t.Error("expected non-empty summary")
			}
		}
	}
	if !found {
		t.Error("expected file-modified finding")
	}
}

func TestDetectsRemovedFile(t *testing.T) {
	cfg := testModuleConfig(t)
	testFile := filepath.Join(t.TempDir(), "willdelete")
	os.WriteFile(testFile, []byte("data"), 0644)

	m := New()
	m.Init(cfg)
	m.watchList = []string{testFile}

	// Baseline
	m.Scan(context.Background())

	// Remove file
	os.Remove(testFile)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "file-removed:"+testFile {
			found = true
		}
	}
	if !found {
		t.Error("expected file-removed finding")
	}
}

func TestDetectsNewFile(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	existingFile := filepath.Join(dir, "existing")
	os.WriteFile(existingFile, []byte("data"), 0644)

	m := New()
	m.Init(cfg)
	m.watchList = []string{filepath.Join(dir, "*")}

	// Baseline with glob
	m.Scan(context.Background())

	// Add new file matching glob
	newFile := filepath.Join(dir, "newfile")
	os.WriteFile(newFile, []byte("new"), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "file-added:"+newFile {
			found = true
		}
	}
	if !found {
		t.Error("expected file-added finding")
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	testFile := filepath.Join(t.TempDir(), "rebase")
	os.WriteFile(testFile, []byte("original"), 0644)

	m := New()
	m.Init(cfg)
	m.watchList = []string{testFile}

	// Baseline
	m.Scan(context.Background())

	// Modify
	os.WriteFile(testFile, []byte("changed"), 0644)

	// Rebaseline
	m.Rebaseline(context.Background())

	// Scan should be clean
	findings, _ := m.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after rebaseline, got %d", len(findings))
	}
}

func TestSensitivePath(t *testing.T) {
	if !isSensitivePath("/etc/shadow") {
		t.Error("/etc/shadow should be sensitive")
	}
	if isSensitivePath("/tmp/foo") {
		t.Error("/tmp/foo should not be sensitive")
	}
}
