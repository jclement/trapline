package fileintegrity

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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

	// Backdate the file's mtime so that the mtime-based fast-path in Scan()
	// reliably detects a change after the subsequent WriteFile.
	past := time.Now().Add(-2 * time.Second)
	os.Chtimes(testFile, past, past)

	m := New()
	m.Init(cfg)
	m.watchList = []string{testFile}

	// First scan - baseline
	m.Scan(context.Background())

	// Modify file (mtime will be "now", different from the backdated baseline)
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

func TestInotifyDetectsChange(t *testing.T) {
	cfg := testModuleConfig(t)
	testFile := filepath.Join(t.TempDir(), "inotify-watched")
	os.WriteFile(testFile, []byte("original"), 0644)

	// Backdate the file so the baseline mtime is clearly in the past
	past := time.Now().Add(-2 * time.Second)
	os.Chtimes(testFile, past, past)

	m := New()
	if err := m.Init(cfg); err != nil {
		t.Fatalf("Init() error: %v", err)
	}
	// Override watchList to target our test file, then restart watcher
	m.Close()
	m.watchList = []string{testFile}
	m.watcher = nil
	m.cancelWatch = nil
	m.startWatcher()
	defer m.Close()

	if m.watcher == nil {
		t.Skip("inotify watcher could not be created (unsupported environment)")
	}

	// First scan to establish baseline
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings in learning mode, got %d", len(findings))
	}

	// Modify file — inotify should detect it
	os.WriteFile(testFile, []byte("modified-by-inotify"), 0644)

	// Give the watcher goroutine a moment to process the event
	time.Sleep(200 * time.Millisecond)

	// Check pending findings directly (without a full Scan)
	m.pendingMu.Lock()
	pending := len(m.pendingFindings)
	m.pendingMu.Unlock()

	if pending == 0 {
		t.Fatal("expected inotify to detect file change, but no pending findings")
	}

	// Now drain via Scan and verify
	findings, err = m.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	foundInotify := false
	foundAny := false
	for _, f := range findings {
		if f.FindingID == "file-modified:"+testFile {
			foundAny = true
			if detail := f.Detail; detail != nil && detail["source"] == "inotify" {
				foundInotify = true
			}
		}
	}
	if !foundAny {
		t.Fatal("expected file-modified finding")
	}
	if !foundInotify {
		t.Error("expected at least one file-modified finding with source=inotify")
	}
}

func TestCloseWithNilWatcher(t *testing.T) {
	// Close() should be safe on a module with no watcher
	m := New()
	m.Close() // should not panic
}

func TestSensitivePath(t *testing.T) {
	if !isSensitivePath("/etc/shadow") {
		t.Error("/etc/shadow should be sensitive")
	}
	if isSensitivePath("/tmp/foo") {
		t.Error("/tmp/foo should not be sensitive")
	}
}
