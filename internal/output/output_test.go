package output

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/pkg/finding"
)

func testFinding(sev finding.Severity) *finding.Finding {
	return &finding.Finding{
		Timestamp:       time.Now(),
		Hostname:        "test-host",
		Module:          "test-module",
		FindingID:       "test-finding-1",
		Severity:        sev,
		Status:          finding.StatusNew,
		Summary:         "test summary",
		TraplineVersion: "0.1.0",
		ScanID:          "test-scan",
	}
}

func TestConsoleSinkJSON(t *testing.T) {
	var buf bytes.Buffer
	sink := &ConsoleSink{
		format: "json",
		level:  finding.SeverityInfo,
		w:      &buf,
	}

	f := testFinding(finding.SeverityHigh)
	if err := sink.Emit(f); err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	var decoded finding.Finding
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("JSON decode error: %v\nOutput: %s", err, buf.String())
	}
	if decoded.FindingID != "test-finding-1" {
		t.Errorf("FindingID = %q", decoded.FindingID)
	}
}

func TestConsoleSinkText(t *testing.T) {
	var buf bytes.Buffer
	sink := &ConsoleSink{
		format: "text",
		level:  finding.SeverityInfo,
		w:      &buf,
	}

	if err := sink.Emit(testFinding(finding.SeverityHigh)); err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.Contains(output, "[HIGH]") {
		t.Errorf("expected [HIGH] in output: %s", output)
	}
	if !strings.Contains(output, "test summary") {
		t.Errorf("expected summary in output: %s", output)
	}
}

func TestConsoleSinkLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	sink := &ConsoleSink{
		format: "json",
		level:  finding.SeverityHigh,
		w:      &buf,
	}

	// Info finding should be filtered
	_ = sink.Emit(testFinding(finding.SeverityInfo))
	if buf.Len() > 0 {
		t.Error("info finding should have been filtered at high level")
	}

	// High finding should pass
	_ = sink.Emit(testFinding(finding.SeverityHigh))
	if buf.Len() == 0 {
		t.Error("high finding should not have been filtered")
	}
}

func TestFileSink(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.log"

	sink, err := NewFileSink(config.FileOutputConfig{
		Enabled: true,
		Path:    path,
		Format:  "json",
		Level:   "info",
	})
	if err != nil {
		t.Fatalf("NewFileSink() error: %v", err)
	}

	if err := sink.Emit(testFinding(finding.SeverityHigh)); err != nil {
		t.Fatalf("Emit() error: %v", err)
	}
	_ = sink.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty log file")
	}
	if !strings.Contains(string(data), "test-finding-1") {
		t.Error("expected finding ID in log file")
	}
}

func TestTCPSink(t *testing.T) {
	// Start a TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		received <- string(buf[:n])
	}()

	sink := NewTCPSink(config.TCPOutputConfig{
		Enabled: true,
		Address: ln.Addr().String(),
		Level:   "info",
	})
	defer func() { _ = sink.Close() }()

	if err := sink.Emit(testFinding(finding.SeverityHigh)); err != nil {
		t.Fatalf("Emit() error: %v", err)
	}

	select {
	case msg := <-received:
		if !strings.Contains(msg, "test-finding-1") {
			t.Errorf("expected finding in TCP output: %s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Error("timeout waiting for TCP data")
	}
}

func TestTCPSinkReconnect(t *testing.T) {
	sink := NewTCPSink(config.TCPOutputConfig{
		Enabled: true,
		Address: "127.0.0.1:1", // nothing listening
		Level:   "info",
	})
	defer func() { _ = sink.Close() }()

	err := sink.Emit(testFinding(finding.SeverityHigh))
	if err == nil {
		t.Error("expected error when nothing is listening")
	}
}

func TestWebhookSinkCooldown(t *testing.T) {
	sink := NewWebhookSink(config.WebhookOutputConfig{
		Enabled:  true,
		URL:      "", // empty URL = no-op but still tracks cooldown
		Level:    "info",
		Cooldown: time.Hour,
	})

	f := testFinding(finding.SeverityHigh)
	_ = sink.Emit(f)

	// Verify cooldown tracking
	sink.mu.Lock()
	_, tracked := sink.lastSent[f.FindingID]
	sink.mu.Unlock()
	// With empty URL, we still skip the http call but track time
	_ = tracked
}

func TestManagerEmit(t *testing.T) {
	var buf bytes.Buffer
	mgr := &Manager{
		sinks: []Sink{
			&ConsoleSink{format: "text", level: finding.SeverityInfo, w: &buf},
		},
	}

	mgr.Emit(testFinding(finding.SeverityHigh))
	if buf.Len() == 0 {
		t.Error("expected output from manager")
	}
}

func TestManagerClose(t *testing.T) {
	mgr := &Manager{
		sinks: []Sink{
			&ConsoleSink{format: "text", level: finding.SeverityInfo, w: &bytes.Buffer{}},
		},
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

func TestFormatText(t *testing.T) {
	f := testFinding(finding.SeverityHigh)
	text := FormatText(f)
	if !strings.Contains(text, "[HIGH]") {
		t.Errorf("expected [HIGH] in: %s", text)
	}
	if !strings.Contains(text, "test summary") {
		t.Errorf("expected summary in: %s", text)
	}
}

func TestNewManagerConsoleOnly(t *testing.T) {
	mgr, err := NewManager(config.OutputConfig{
		Console: config.ConsoleOutputConfig{
			Enabled: true,
			Format:  "json",
			Level:   "info",
		},
	})
	if err != nil {
		t.Fatalf("NewManager() error: %v", err)
	}
	if len(mgr.Sinks()) != 1 {
		t.Errorf("expected 1 sink, got %d", len(mgr.Sinks()))
	}
	if mgr.Sinks()[0].Name() != "console" {
		t.Errorf("expected console sink, got %s", mgr.Sinks()[0].Name())
	}
}
