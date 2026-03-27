package packages

import (
	"context"
	"os/exec"
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

func TestName(t *testing.T) {
	if New().Name() != "packages" {
		t.Error("wrong name")
	}
}

func TestScanWithMockVerify(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

	m.VerifyCmd = func(ctx context.Context) ([]byte, error) {
		return []byte("??5?????? c /usr/sbin/sshd\n??5?????? c /etc/ssh/sshd_config\n"), nil
	}

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// /etc/ssh/sshd_config should be excluded (starts with /etc/)
	// /usr/sbin/sshd should be reported
	sshd := false
	etcFile := false
	for _, f := range findings {
		if f.FindingID == "package-file-modified:/usr/sbin/sshd" {
			sshd = true
			if f.Severity != finding.SeverityHigh {
				t.Errorf("severity = %s, want high", f.Severity)
			}
		}
		if f.FindingID == "package-file-modified:/etc/ssh/sshd_config" {
			etcFile = true
		}
	}
	if !sshd {
		t.Error("expected finding for /usr/sbin/sshd")
	}
	if etcFile {
		t.Error("/etc/ssh/sshd_config should be excluded")
	}
}

func TestScanClean(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

	m.VerifyCmd = func(ctx context.Context) ([]byte, error) {
		return []byte(""), nil
	}

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean system, got %d", len(findings))
	}
}

func TestScanDpkgUnavailable(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

	m.VerifyCmd = func(ctx context.Context) ([]byte, error) {
		return nil, &exec.Error{Name: "dpkg", Err: exec.ErrNotFound}
	}

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when dpkg unavailable, got %d", len(findings))
	}
}

func TestRebaselineNoOp(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	_ = m.Init(cfg)
	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
}
