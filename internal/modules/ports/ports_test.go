package ports

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
	if New().Name() != "ports" {
		t.Error("wrong name")
	}
}

func TestParseHexAddr(t *testing.T) {
	// 0.0.0.0:22 in hex
	addr, port, err := parseHexAddr("00000000:0016")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0" {
		t.Errorf("addr = %q, want 0.0.0.0", addr)
	}
	if port != 22 {
		t.Errorf("port = %d, want 22", port)
	}
}

func TestParseHexAddrLocalhost(t *testing.T) {
	// 127.0.0.1:5432 -> 0100007F:1538
	addr, port, err := parseHexAddr("0100007F:1538")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1" {
		t.Errorf("addr = %q, want 127.0.0.1", addr)
	}
	if port != 5432 {
		t.Errorf("port = %d, want 5432", port)
	}
}

func TestParseProcNet(t *testing.T) {
	// Create a fake /proc/net/tcp
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000   111        0 23456 1 0000000000000000 100 0 0 10 0
   2: 00000000:0050 0100007F:9876 01 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	os.WriteFile(path, []byte(content), 0644)

	entries, err := parseProcNet(path, "tcp")
	if err != nil {
		t.Fatal(err)
	}

	// Should only include LISTEN (0A) entries, not ESTABLISHED (01)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Port != 22 {
		t.Errorf("first port = %d, want 22", entries[0].Port)
	}
	if entries[1].Port != 5432 {
		t.Errorf("second port = %d, want 5432", entries[1].Port)
	}
}

func TestScanWithFakeProc(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	tcpContent := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
`
	tcpPath := filepath.Join(dir, "tcp")
	os.WriteFile(tcpPath, []byte(tcpContent), 0644)

	m := New()
	m.ProcTCP = tcpPath
	m.ProcTCP6 = filepath.Join(dir, "nonexistent")
	m.ProcUDP = filepath.Join(dir, "nonexistent")
	m.ProcUDP6 = filepath.Join(dir, "nonexistent")

	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

	// First scan = learning
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}

	// Same scan again = no changes
	findings, _ = m.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for no change, got %d", len(findings))
	}
}

func TestDetectsNewPort(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	tcpPath := filepath.Join(dir, "tcp")
	os.WriteFile(tcpPath, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
`), 0644)

	m := New()
	m.ProcTCP = tcpPath
	m.ProcTCP6 = filepath.Join(dir, "none")
	m.ProcUDP = filepath.Join(dir, "none")
	m.ProcUDP6 = filepath.Join(dir, "none")

	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Add a new port
	os.WriteFile(tcpPath, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 45678 1 0000000000000000 100 0 0 10 0
`), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "port-new:tcp:8080" {
			found = true
		}
	}
	if !found {
		t.Error("expected port-new finding for port 8080")
	}
}

func TestDetectsGonePort(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	tcpPath := filepath.Join(dir, "tcp")
	os.WriteFile(tcpPath, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0
`), 0644)

	m := New()
	m.ProcTCP = tcpPath
	m.ProcTCP6 = filepath.Join(dir, "none")
	m.ProcUDP = filepath.Join(dir, "none")
	m.ProcUDP6 = filepath.Join(dir, "none")

	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Remove port 80
	os.WriteFile(tcpPath, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
`), 0644)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "port-gone:tcp:80" {
			found = true
		}
	}
	if !found {
		t.Error("expected port-gone finding for port 80")
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	tcpPath := filepath.Join(dir, "tcp")
	os.WriteFile(tcpPath, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
`), 0644)

	m := New()
	m.ProcTCP = tcpPath
	m.ProcTCP6 = filepath.Join(dir, "none")
	m.ProcUDP = filepath.Join(dir, "none")
	m.ProcUDP6 = filepath.Join(dir, "none")

	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Add port then rebaseline
	os.WriteFile(tcpPath, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 45678 1 0000000000000000 100 0 0 10 0
`), 0644)

	m.Rebaseline(context.Background())
	findings, _ := m.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after rebaseline, got %d", len(findings))
	}
}

func TestPortsToMap(t *testing.T) {
	ports := []PortEntry{
		{Proto: "tcp", Address: "0.0.0.0", Port: 22},
		{Proto: "tcp", Address: "0.0.0.0", Port: 80},
	}
	m := portsToMap(ports)
	if len(m) != 2 {
		t.Errorf("expected 2 entries, got %d", len(m))
	}
}
