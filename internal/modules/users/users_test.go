package users

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

const testPasswd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
`

const testGroup = `root:x:0:
sudo:x:27:admin
docker:x:999:admin
`

func setupTestFiles(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	groupPath := filepath.Join(dir, "group")
	sudoersPath := filepath.Join(dir, "sudoers")

	os.WriteFile(passwdPath, []byte(testPasswd), 0644)
	os.WriteFile(groupPath, []byte(testGroup), 0644)
	os.WriteFile(sudoersPath, []byte("root ALL=(ALL:ALL) ALL\n"), 0644)

	return passwdPath, groupPath, sudoersPath
}

func TestName(t *testing.T) {
	if New().Name() != "users" {
		t.Error("wrong name")
	}
}

func TestLearningMode(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}
}

func TestDetectsNewUser(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Add a new user
	os.WriteFile(passwdPath, []byte(testPasswd+"hacker:x:1001:1001::/home/hacker:/bin/bash\n"), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "user-added:hacker" {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %s, want high", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected user-added finding")
	}
}

func TestDetectsUID0User(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)
	m.Scan(context.Background())

	// Add user with UID 0
	os.WriteFile(passwdPath, []byte(testPasswd+"backdoor:x:0:0::/root:/bin/bash\n"), 0644)

	findings, _ := m.Scan(context.Background())
	for _, f := range findings {
		if f.FindingID == "user-added:backdoor" {
			if f.Severity != finding.SeverityCritical {
				t.Errorf("UID 0 user should be critical, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected user-added finding for UID 0 user")
}

func TestDetectsRemovedUser(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)
	m.Scan(context.Background())

	// Remove nobody
	os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "user-removed:nobody" {
			found = true
		}
	}
	if !found {
		t.Error("expected user-removed finding")
	}
}

func TestDetectsShellChange(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)
	m.Scan(context.Background())

	// Change daemon's shell
	os.WriteFile(passwdPath, []byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "user-shell-changed:daemon" {
			found = true
		}
	}
	if !found {
		t.Error("expected user-shell-changed finding")
	}
}

func TestDetectsSudoersChange(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)
	m.Scan(context.Background())

	// Modify sudoers
	os.WriteFile(sudoersPath, []byte("root ALL=(ALL:ALL) ALL\nhacker ALL=(ALL) NOPASSWD:ALL\n"), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "sudoers-modified" {
			found = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("sudoers change should be high severity")
			}
		}
	}
	if !found {
		t.Error("expected sudoers-modified finding")
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	passwdPath, groupPath, sudoersPath := setupTestFiles(t)

	m := New()
	m.PasswdPath = passwdPath
	m.GroupPath = groupPath
	m.SudoersPath = sudoersPath
	m.Init(cfg)
	m.Scan(context.Background())

	os.WriteFile(passwdPath, []byte(testPasswd+"newuser:x:1001:1001::/home/newuser:/bin/bash\n"), 0644)
	m.Rebaseline(context.Background())

	findings, _ := m.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after rebaseline, got %d", len(findings))
	}
}

func TestParsePasswd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	os.WriteFile(path, []byte(testPasswd), 0644)

	users, err := parsePasswd(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Errorf("expected 3 users, got %d", len(users))
	}
	if users[0].Name != "root" || users[0].UID != "0" {
		t.Errorf("first user: %+v", users[0])
	}
}

func TestParseGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "group")
	os.WriteFile(path, []byte(testGroup), 0644)

	groups, err := parseGroup(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 {
		t.Errorf("expected 3 groups, got %d", len(groups))
	}
}
