package ssh

import (
	"context"
	"os"
	"path/filepath"
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

const secureConfig = `Port 22
PasswordAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication yes
`

const insecureConfig = `Port 22
PasswordAuthentication yes
PermitRootLogin yes
PermitEmptyPasswords yes
`

func TestName(t *testing.T) {
	if New().Name() != "ssh" {
		t.Error("wrong name")
	}
}

func TestSecureConfig(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	os.WriteFile(configPath, []byte(secureConfig), 0644)

	m := New()
	m.ConfigPath = configPath
	m.Init(cfg)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range findings {
		if f.FindingID != "ssh-config-changed" {
			t.Errorf("unexpected finding for secure config: %s", f.FindingID)
		}
	}
}

func TestInsecureConfig(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	os.WriteFile(configPath, []byte(insecureConfig), 0644)

	m := New()
	m.ConfigPath = configPath
	m.Init(cfg)

	findings, _ := m.Scan(context.Background())

	insecureFindings := 0
	for _, f := range findings {
		if f.Severity == finding.SeverityHigh && f.FindingID != "ssh-config-changed" {
			insecureFindings++
		}
	}
	if insecureFindings != 3 {
		t.Errorf("expected 3 insecure findings, got %d", insecureFindings)
	}
}

func TestDetectsConfigChange(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	os.WriteFile(configPath, []byte(secureConfig), 0644)

	m := New()
	m.ConfigPath = configPath
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	os.WriteFile(configPath, []byte(secureConfig+"AllowUsers admin\n"), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "ssh-config-changed" {
			found = true
		}
	}
	if !found {
		t.Error("expected ssh-config-changed finding")
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	os.WriteFile(configPath, []byte(secureConfig), 0644)

	m := New()
	m.ConfigPath = configPath
	m.Init(cfg)
	m.Scan(context.Background())

	os.WriteFile(configPath, []byte(secureConfig+"Match User deploy\n"), 0644)
	m.Rebaseline(context.Background())

	findings, _ := m.Scan(context.Background())
	for _, f := range findings {
		if f.FindingID == "ssh-config-changed" {
			t.Error("should not detect change after rebaseline")
		}
	}
}

func TestParseSSHConfig(t *testing.T) {
	settings := parseSSHConfig(secureConfig)
	if settings["passwordauthentication"] != "no" {
		t.Errorf("PasswordAuthentication = %q", settings["passwordauthentication"])
	}
	if settings["permitrootlogin"] != "no" {
		t.Errorf("PermitRootLogin = %q", settings["permitrootlogin"])
	}
}

func TestMissingConfig(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	m.ConfigPath = "/nonexistent/sshd_config"
	m.Init(cfg)

	// Should not error, just return no findings
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing config, got %d", len(findings))
	}
}
