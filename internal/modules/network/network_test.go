package network

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

func writeProcFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const procHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func newTestModule(t *testing.T, tcpPath, tcp6Path string) *Module {
	t.Helper()
	m := New()
	m.ProcTCP = tcpPath
	m.ProcTCP6 = tcp6Path
	return m
}

func TestName(t *testing.T) {
	if New().Name() != "network" {
		t.Error("wrong name")
	}
}

func TestParseEstablishedConnections(t *testing.T) {
	dir := t.TempDir()
	// 10.0.2.15:40000 -> 216.58.196.78:443 ESTABLISHED (01)
	// IPv4 little-endian: 10.0.2.15 = 0A.00.02.0F -> 0F02000A
	// 216.58.196.78 = D8.3A.C4.4E -> 4EC43AD8
	// port 40000 = 0x9C40, port 443 = 0x01BB
	content := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"

	tcpPath := writeProcFile(t, dir, "tcp", content)
	conns, err := parseEstablished(tcpPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	c := conns[0]
	if c.LocalAddr != "10.0.2.15" {
		t.Errorf("local addr = %q, want 10.0.2.15", c.LocalAddr)
	}
	if c.LocalPort != 40000 {
		t.Errorf("local port = %d, want 40000", c.LocalPort)
	}
	if c.RemoteAddr != "216.58.196.78" {
		t.Errorf("remote addr = %q, want 216.58.196.78", c.RemoteAddr)
	}
	if c.RemotePort != 443 {
		t.Errorf("remote port = %d, want 443", c.RemotePort)
	}
	if c.State != "ESTABLISHED" {
		t.Errorf("state = %q, want ESTABLISHED", c.State)
	}
}

func TestIgnoresListeningPorts(t *testing.T) {
	dir := t.TempDir()
	// State 0A = LISTEN, should be ignored
	content := procHeader +
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"

	tcpPath := writeProcFile(t, dir, "tcp", content)
	conns, err := parseEstablished(tcpPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 0 {
		t.Errorf("expected 0 connections (LISTEN should be ignored), got %d", len(conns))
	}
}

func TestLearningMode(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Outbound to 216.58.196.78:443
	content := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"

	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))

	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}
	if !m.baseline.Initialized {
		t.Error("baseline should be initialized after first scan")
	}
	if !m.baseline.KnownRemoteIPs["216.58.196.78"] {
		t.Error("baseline should contain 216.58.196.78")
	}
}

func TestDetectsNewOutbound(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Initial: connection to 216.58.196.78:443
	content := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"

	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Add new connection to 93.184.216.34:80
	// 93.184.216.34 = 5D.B8.D8.22 -> little-endian 22D8B85D
	// port 80 = 0x0050
	content2 := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0F02000A:A000 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].FindingID != "network-new-outbound:93.184.216.34" {
		t.Errorf("finding ID = %q, want network-new-outbound:93.184.216.34", findings[0].FindingID)
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
}

func TestIgnoresLoopback(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Start with empty baseline (no public connections)
	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Add connection to 127.0.0.1:8080
	// 127.0.0.1 = 7F.00.00.01 -> little-endian 0100007F
	content2 := procHeader +
		"   0: 0F02000A:C000 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for loopback connection, got %d", len(findings))
	}
}

func TestIgnoresPrivateRanges(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// 10.0.0.1 = 0A.00.00.01 -> little-endian 0100000A
	// 172.16.0.1 = AC.10.00.01 -> little-endian 010010AC
	// 192.168.1.1 = C0.A8.01.01 -> little-endian 0101A8C0
	content2 := procHeader +
		"   0: 0F02000A:C000 0100000A:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0F02000A:C001 010010AC:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n" +
		"   2: 0F02000A:C002 0101A8C0:0050 01 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for private range connections, got %d", len(findings))
	}
}

func TestMultipleNewConnections(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Two new public IPs: 216.58.196.78 and 93.184.216.34
	content2 := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0F02000A:A000 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	// Multiple new connections should be critical
	for _, f := range findings {
		if f.Severity != "critical" {
			t.Errorf("severity = %q, want critical for multi-connection burst", f.Severity)
		}
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.Init(cfg)
	m.Scan(context.Background()) // baseline (empty)

	// Add a new public IP
	content2 := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	// Verify it would trigger
	findings, _ := m.Scan(context.Background())
	if len(findings) == 0 {
		t.Fatal("expected finding before rebaseline")
	}

	// Rebaseline
	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Same connections should no longer trigger
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after rebaseline, got %d", len(findings))
	}
}

func TestIPv6Parsing(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)

	// IPv6 connection to 2607:f8b0:4004:0800:0000:0000:0000:200e (a Google IP)
	// In /proc/net/tcp6, each 4-byte group is little-endian:
	// 2607:f8b0 -> bytes 26 07 f8 b0 -> little-endian group: B0F80726
	// 4004:0800 -> bytes 40 04 08 00 -> little-endian group: 00080440
	// 0000:0000 -> bytes 00 00 00 00 -> little-endian group: 00000000
	// 0000:200e -> bytes 00 00 20 0e -> little-endian group: 0E200000
	tcp6Content := procHeader +
		"   0: 00000000000000000000000000000000:C000 B0F8072600080440000000000E200000:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"

	tcp6Path := writeProcFile(t, dir, "tcp6", tcp6Content)
	m := newTestModule(t, tcpPath, tcp6Path)
	m.Init(cfg)

	// First scan = learning
	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in learning mode, got %d", len(findings))
	}
	if !m.baseline.KnownRemoteIPs["2607:f8b0:4004:800::200e"] {
		// Check what IP was actually stored
		for ip := range m.baseline.KnownRemoteIPs {
			t.Logf("baseline contains IP: %s", ip)
		}
		t.Error("baseline should contain the IPv6 address")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.15.0.1", false},
		{"172.32.0.1", false},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"216.58.196.78", false},
		{"93.184.216.34", false},
		{"0.0.0.0", true},
		{"::1", true},
		{"::", true},
		{"fc00::1", true},
		{"2607:f8b0:4004:800::200e", false},
	}

	for _, tt := range tests {
		got := isPrivateIP(tt.ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestSameIPDifferentPort(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Baseline: connection to 216.58.196.78:443
	content := procHeader +
		"   0: 0F02000A:9C40 4EC43AD8:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.Init(cfg)
	m.Scan(context.Background()) // baseline

	// Same IP, different port (80 = 0x0050)
	content2 := procHeader +
		"   0: 0F02000A:A000 4EC43AD8:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for same IP different port, got %d", len(findings))
	}
}
