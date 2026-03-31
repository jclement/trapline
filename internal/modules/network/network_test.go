package network

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jclement/trapline/internal/engine"
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
	m.ProcDir = t.TempDir() // empty dir = no process resolution
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
	if c.Inode != "12345" {
		t.Errorf("inode = %q, want 12345", c.Inode)
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
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Scan(context.Background()); err != nil {
		t.Fatal(err)
	} // baseline

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
	if findings[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

func TestIgnoresLoopback(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Start with empty baseline (no public connections)
	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Scan(context.Background()); err != nil {
		t.Fatal(err)
	} // baseline

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
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Scan(context.Background()); err != nil {
		t.Fatal(err)
	} // baseline

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
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Scan(context.Background()) // baseline

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
	// Multiple new connections should be high
	for _, f := range findings {
		if f.Severity != "high" {
			t.Errorf("severity = %q, want high for multi-connection burst", f.Severity)
		}
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Scan(context.Background()) // baseline (empty)

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

func TestBuildInodeMap(t *testing.T) {
	procDir := t.TempDir()

	// Create fake /proc/1234/ with socket symlinks
	pid1Dir := filepath.Join(procDir, "1234")
	fdDir1 := filepath.Join(pid1Dir, "fd")
	if err := os.MkdirAll(fdDir1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid1Dir, "comm"), []byte("curl\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/curl", filepath.Join(pid1Dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[12345]", filepath.Join(fdDir1, "3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(fdDir1, "4")); err != nil {
		t.Fatal(err)
	}

	// Create another process
	pid2Dir := filepath.Join(procDir, "5678")
	fdDir2 := filepath.Join(pid2Dir, "fd")
	if err := os.MkdirAll(fdDir2, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid2Dir, "comm"), []byte("sshd\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/sbin/sshd", filepath.Join(pid2Dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[99999]", filepath.Join(fdDir2, "5")); err != nil {
		t.Fatal(err)
	}

	m := buildInodeMap(procDir)

	if proc, ok := m["12345"]; !ok {
		t.Error("expected to find inode 12345")
	} else {
		if proc.Name != "curl" {
			t.Errorf("expected name 'curl', got %q", proc.Name)
		}
		if proc.ExePath != "/usr/bin/curl" {
			t.Errorf("expected exe path '/usr/bin/curl', got %q", proc.ExePath)
		}
		if proc.PID != 1234 {
			t.Errorf("expected PID 1234, got %d", proc.PID)
		}
	}

	if proc, ok := m["99999"]; !ok {
		t.Error("expected to find inode 99999")
	} else if proc.Name != "sshd" {
		t.Errorf("expected name 'sshd', got %q", proc.Name)
	}

	if _, ok := m["00000"]; ok {
		t.Error("expected not found for non-existent inode")
	}
}

func TestAllowedProcessFiltering(t *testing.T) {
	cfg := testModuleConfig(t)
	cfg.Settings["allowed_processes"] = []interface{}{"apt"}

	dir := t.TempDir()
	procDir := t.TempDir()

	// Create fake process: PID 100 = "apt"
	pid100Dir := filepath.Join(procDir, "100")
	fdDir := filepath.Join(pid100Dir, "fd")
	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid100Dir, "comm"), []byte("apt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/apt", filepath.Join(pid100Dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[23456]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}

	// Baseline: empty
	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.ProcDir = procDir
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Scan(context.Background()) // baseline

	// New connection with inode 23456 (owned by apt) to 93.184.216.34:80
	content2 := procHeader +
		"   0: 0F02000A:A000 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for allowlisted process apt, got %d", len(findings))
	}
}

func TestProcessInfoInFindings(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	procDir := t.TempDir()

	// Create fake process: PID 200 = "curl"
	pid200Dir := filepath.Join(procDir, "200")
	fdDir := filepath.Join(pid200Dir, "fd")
	if err := os.MkdirAll(fdDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pid200Dir, "comm"), []byte("curl\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/curl", filepath.Join(pid200Dir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[23456]", filepath.Join(fdDir, "5")); err != nil {
		t.Fatal(err)
	}

	// Baseline: empty
	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	m.ProcDir = procDir
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Scan(context.Background()) // baseline

	// New connection with inode 23456 (owned by curl) to 93.184.216.34:80
	content2 := procHeader +
		"   0: 0F02000A:A000 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if !strings.Contains(f.Summary, "/usr/bin/curl") {
		t.Errorf("expected summary to contain '/usr/bin/curl', got %q", f.Summary)
	}
	if f.Detail["process_name"] != "curl" {
		t.Errorf("expected detail process_name='curl', got %v", f.Detail["process_name"])
	}
	if f.Detail["process_path"] != "/usr/bin/curl" {
		t.Errorf("expected detail process_path='/usr/bin/curl', got %v", f.Detail["process_path"])
	}
	if f.Detail["process_pid"] != 200 {
		t.Errorf("expected detail process_pid=200, got %v", f.Detail["process_pid"])
	}
}

func TestUnknownProcessInFindings(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	// Baseline: empty
	content := procHeader
	tcpPath := writeProcFile(t, dir, "tcp", content)
	m := newTestModule(t, tcpPath, filepath.Join(dir, "nonexistent"))
	// ProcDir already set to empty temp dir — no process matches
	if err := m.Init(cfg); err != nil {
		t.Fatal(err)
	}
	_, _ = m.Scan(context.Background()) // baseline

	// New connection with unresolvable inode
	content2 := procHeader +
		"   0: 0F02000A:A000 22D8B85D:0050 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n"
	writeProcFile(t, dir, "tcp", content2)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Detail["process_name"] != "unknown" {
		t.Errorf("expected process_name='unknown', got %v", findings[0].Detail["process_name"])
	}
	if !strings.Contains(findings[0].Summary, "unknown") {
		t.Errorf("expected summary to contain 'unknown', got %q", findings[0].Summary)
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
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background()) // baseline

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
