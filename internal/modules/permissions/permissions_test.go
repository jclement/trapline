package permissions

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
	if New().Name() != "permissions" {
		t.Error("wrong name")
	}
}

func TestDetectsWorldWritable(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Create a world-writable file
	badFile := filepath.Join(dir, "bad")
	os.WriteFile(badFile, []byte("data"), 0644)
	os.Chmod(badFile, 0666)

	m := New()
	m.scanPaths = []string{dir}
	m.Init(cfg)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range findings {
		if f.FindingID == "perm-world-writable:"+badFile {
			found = true
		}
	}
	if !found {
		t.Error("expected perm-world-writable finding")
	}
}

func TestCleanDirectory(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Create a normal file
	os.WriteFile(filepath.Join(dir, "good"), []byte("data"), 0644)

	m := New()
	m.scanPaths = []string{dir}
	m.Init(cfg)

	findings, _ := m.Scan(context.Background())
	// Filter to only perm-world-writable findings in our dir
	wwFindings := 0
	for _, f := range findings {
		if f.FindingID == "perm-world-writable:"+filepath.Join(dir, "good") {
			wwFindings++
		}
	}
	if wwFindings != 0 {
		t.Errorf("expected 0 world-writable findings for 0644 file, got %d", wwFindings)
	}
}

func TestCancellation(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	m.scanPaths = []string{t.TempDir()}
	m.Init(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.Scan(ctx)
}

func TestRebaselineNoOp(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	m.scanPaths = nil
	m.Init(cfg)

	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
}
