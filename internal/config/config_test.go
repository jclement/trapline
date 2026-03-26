package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.StateDir != "/var/lib/trapline" {
		t.Errorf("StateDir = %q, want /var/lib/trapline", cfg.StateDir)
	}
	if !cfg.Output.Console.Enabled {
		t.Error("Console output should be enabled by default")
	}
	if cfg.Defaults.Interval != 5*time.Minute {
		t.Errorf("Default interval = %v, want 5m", cfg.Defaults.Interval)
	}
	if len(cfg.Modules) != 10 {
		t.Errorf("Default modules count = %d, want 10", len(cfg.Modules))
	}
}

func TestLoad(t *testing.T) {
	yaml := `
state_dir: /tmp/trapline-test
output:
  console:
    enabled: true
    format: text
    level: info
defaults:
  interval: 10s
  cooldown: 30s
modules:
  file-integrity:
    enabled: true
    interval: 5s
  ports:
    enabled: false
`
	dir := t.TempDir()
	path := filepath.Join(dir, "trapline.yml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.StateDir != "/tmp/trapline-test" {
		t.Errorf("StateDir = %q", cfg.StateDir)
	}
	if cfg.Output.Console.Format != "text" {
		t.Errorf("Console format = %q", cfg.Output.Console.Format)
	}
	if cfg.Defaults.Interval != 10*time.Second {
		t.Errorf("Default interval = %v", cfg.Defaults.Interval)
	}
	if !cfg.ModuleEnabled("file-integrity") {
		t.Error("file-integrity should be enabled")
	}
	if cfg.ModuleEnabled("ports") {
		t.Error("ports should be disabled")
	}
	if cfg.ModuleInterval("file-integrity") != 5*time.Second {
		t.Errorf("file-integrity interval = %v", cfg.ModuleInterval("file-integrity"))
	}
}

func TestLoadMissing(t *testing.T) {
	_, err := Load("/nonexistent/trapline.yml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestValidateEmptyStateDir(t *testing.T) {
	cfg := Default()
	cfg.StateDir = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty state_dir")
	}
}

func TestModuleIntervalFallback(t *testing.T) {
	cfg := Default()
	// Unknown module should fall back to default interval
	if cfg.ModuleInterval("nonexistent") != cfg.Defaults.Interval {
		t.Errorf("unknown module interval = %v, want %v", cfg.ModuleInterval("nonexistent"), cfg.Defaults.Interval)
	}
}

func TestDefaultConfigYAML(t *testing.T) {
	data, err := DefaultConfigYAML()
	if err != nil {
		t.Fatalf("DefaultConfigYAML() error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty default config YAML")
	}
}
