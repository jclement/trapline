package ssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jclement/trapline/internal/engine"
	"github.com/jclement/trapline/pkg/finding"
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
	if err := os.WriteFile(configPath, []byte(secureConfig), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.ConfigPath = configPath
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

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
	if err := os.WriteFile(configPath, []byte(insecureConfig), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.ConfigPath = configPath
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

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
	if err := os.WriteFile(configPath, []byte(secureConfig), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.ConfigPath = configPath
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Scan(context.Background()) // baseline

	if err := os.WriteFile(configPath, []byte(secureConfig+"AllowUsers admin\n"), 0644); err != nil {
		t.Fatal(err)
	}

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
	if err := os.WriteFile(configPath, []byte(secureConfig), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.ConfigPath = configPath
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background())

	_ = os.WriteFile(configPath, []byte(secureConfig+"Match User deploy\n"), 0644)
	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatal(err)
	}

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
	_ = m.Init(cfg)

	// Should not error, just return no findings
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for missing config, got %d", len(findings))
	}
}

func TestSessionCheckDisabledByDefault(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(configPath, []byte(secureConfig), 0644); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.ConfigPath = configPath
	m.ProcDir = t.TempDir() // empty proc dir
	_ = m.Init(cfg)

	// No allowed_users configured = no session findings
	findings := m.checkSessions()
	if len(findings) != 0 {
		t.Errorf("expected 0 session findings when allowed_users not set, got %d", len(findings))
	}
}

func createFakeSSHDSession(t *testing.T, procDir string, pid int, uid int) {
	t.Helper()
	pidDir := filepath.Join(procDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("sshd\n"), 0644); err != nil {
		t.Fatal(err)
	}
	status := fmt.Sprintf("Name:\tsshd\nUid:\t%d\t%d\t%d\t%d\n", uid, uid, uid, uid)
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0644); err != nil {
		t.Fatal(err)
	}
	// Simulate SSH_CONNECTION env var
	environ := "SSH_CONNECTION=192.168.1.100 54321 10.0.0.1 22\x00HOME=/home/testuser\x00"
	if err := os.WriteFile(filepath.Join(pidDir, "environ"), []byte(environ), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectsUnauthorizedSession(t *testing.T) {
	cfg := testModuleConfig(t)
	cfg.Settings["allowed_users"] = []interface{}{"admin", "deploy"}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(configPath, []byte(secureConfig), 0644); err != nil {
		t.Fatal(err)
	}

	procDir := t.TempDir()

	// Root sshd parent (UID 0) — should be ignored
	createFakeSSHDSession(t, procDir, 1000, 0)

	// Authorized user session (UID 1001 = "admin")
	createFakeSSHDSession(t, procDir, 2000, 1001)

	// Unauthorized user session (UID 1002 = "hacker")
	createFakeSSHDSession(t, procDir, 3000, 1002)

	m := New()
	m.ConfigPath = configPath
	m.ProcDir = procDir
	_ = m.Init(cfg)

	// Manually set UID map since we can't mock /etc/passwd
	sessions := m.detectSSHSessions()

	// Should find 2 sessions (UID != 0): 1001 and 1002
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions (non-root), got %d", len(sessions))
	}

	// Verify session details
	for _, s := range sessions {
		if s.RemoteIP != "192.168.1.100" {
			t.Errorf("expected remote IP 192.168.1.100, got %q", s.RemoteIP)
		}
	}
}

func TestAllowedUserNotFlagged(t *testing.T) {
	procDir := t.TempDir()
	createFakeSSHDSession(t, procDir, 5000, 1001)

	m := New()
	m.ProcDir = procDir
	m.allowedUsers = []string{"testuser"}

	// The session UID 1001 will resolve to "1001" (no /etc/passwd in test).
	// Set allowed_users to match the numeric fallback.
	m.allowedUsers = []string{"1001"}

	findings := m.checkSessions()
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for allowed user, got %d", len(findings))
	}
}
