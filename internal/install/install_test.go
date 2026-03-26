package install

import (
	"testing"
)

func TestConstants(t *testing.T) {
	if BinaryPath != "/usr/local/bin/trapline" {
		t.Errorf("BinaryPath = %q", BinaryPath)
	}
	if ConfigDir != "/etc/trapline" {
		t.Errorf("ConfigDir = %q", ConfigDir)
	}
	if ServicePath != "/usr/lib/systemd/system/trapline.service" {
		t.Errorf("ServicePath = %q", ServicePath)
	}
}

func TestSystemdUnit(t *testing.T) {
	if SystemdUnit == "" {
		t.Error("SystemdUnit is empty")
	}
	// Should contain key directives
	checks := []string{
		"ExecStart=/usr/local/bin/trapline run",
		"Restart=on-failure",
		"WantedBy=multi-user.target",
		"WatchdogSec=120",
	}
	for _, check := range checks {
		found := false
		for _, line := range []string{SystemdUnit} {
			if contains(line, check) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("systemd unit missing: %s", check)
		}
	}
}

func TestAptHook(t *testing.T) {
	if AptHook == "" {
		t.Error("AptHook is empty")
	}
	if !contains(AptHook, "trapline rebaseline") {
		t.Error("apt hook should reference trapline rebaseline")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestDoctorResult(t *testing.T) {
	r := &DoctorResult{
		Checks: []Check{
			{Category: "Test", Name: "pass", Status: CheckPassed, Detail: "ok"},
			{Category: "Test", Name: "warn", Status: CheckWarning, Detail: "meh"},
			{Category: "Test", Name: "fail", Status: CheckError, Detail: "bad"},
		},
		Passed:   1,
		Warnings: 1,
		Errors:   1,
	}
	if r.Passed != 1 || r.Warnings != 1 || r.Errors != 1 {
		t.Error("wrong counts")
	}
}

func TestCheckStatus(t *testing.T) {
	if CheckPassed.String() != "✓" {
		t.Errorf("Passed = %q", CheckPassed.String())
	}
	if CheckWarning.String() != "⚠" {
		t.Errorf("Warning = %q", CheckWarning.String())
	}
	if CheckError.String() != "✗" {
		t.Errorf("Error = %q", CheckError.String())
	}
}
