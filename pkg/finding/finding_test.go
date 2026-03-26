package finding

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSeverityLevel(t *testing.T) {
	tests := []struct {
		sev  Severity
		want int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityInfo, 1},
		{Severity("unknown"), 0},
	}
	for _, tt := range tests {
		if got := tt.sev.Level(); got != tt.want {
			t.Errorf("Severity(%q).Level() = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"critical", SeverityCritical},
		{"high", SeverityHigh},
		{"medium", SeverityMedium},
		{"info", SeverityInfo},
		{"bogus", SeverityMedium},
		{"", SeverityMedium},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.input); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFindingJSON(t *testing.T) {
	f := Finding{
		Timestamp: time.Date(2026, 3, 26, 14, 32, 1, 0, time.UTC),
		Hostname:  "nyc1",
		Module:    "file-integrity",
		FindingID: "file-modified:/etc/ssh/sshd_config",
		Severity:  SeverityHigh,
		Status:    StatusNew,
		Summary:   "sshd_config modified",
		Detail: map[string]interface{}{
			"path": "/etc/ssh/sshd_config",
		},
		TraplineVersion: "0.1.0",
		ScanID:          "abc123",
	}

	data, err := f.JSON()
	if err != nil {
		t.Fatalf("JSON() error: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.FindingID != f.FindingID {
		t.Errorf("FindingID = %q, want %q", decoded.FindingID, f.FindingID)
	}
	if decoded.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q", decoded.Severity, SeverityHigh)
	}
	if decoded.Module != "file-integrity" {
		t.Errorf("Module = %q, want %q", decoded.Module, "file-integrity")
	}
}

func TestFindingJSONOmitsEmptyDetail(t *testing.T) {
	f := Finding{
		Timestamp: time.Now(),
		Module:    "test",
		FindingID: "test-1",
		Severity:  SeverityInfo,
		Status:    StatusNew,
		Summary:   "test",
		ScanID:    "x",
	}

	data, err := f.JSON()
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}

	if _, ok := raw["detail"]; ok {
		t.Error("expected detail to be omitted when nil")
	}
	if _, ok := raw["context"]; ok {
		t.Error("expected context to be omitted when nil")
	}
}
