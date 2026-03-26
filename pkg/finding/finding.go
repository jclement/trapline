package finding

import (
	"encoding/json"
	"time"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityInfo     Severity = "info"
)

// Status represents the lifecycle status of a finding.
type Status string

const (
	StatusNew       Status = "new"
	StatusRecurring Status = "recurring"
	StatusResolved  Status = "resolved"
)

// Finding represents a single security finding from a scanner module.
type Finding struct {
	Timestamp       time.Time              `json:"timestamp"`
	Hostname        string                 `json:"hostname"`
	Module          string                 `json:"module"`
	FindingID       string                 `json:"finding_id"`
	Severity        Severity               `json:"severity"`
	Status          Status                 `json:"status"`
	Summary         string                 `json:"summary"`
	Detail          map[string]interface{} `json:"detail,omitempty"`
	Context         map[string]interface{} `json:"context,omitempty"`
	TraplineVersion string                 `json:"trapline_version"`
	ScanID          string                 `json:"scan_id"`
}

// SeverityLevel returns a numeric level for comparison (higher = more severe).
func (s Severity) Level() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ParseSeverity parses a severity string. Returns SeverityMedium if unknown.
func ParseSeverity(s string) Severity {
	switch Severity(s) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityInfo:
		return Severity(s)
	default:
		return SeverityMedium
	}
}

// JSON returns the finding as a JSON byte slice.
func (f *Finding) JSON() ([]byte, error) {
	return json.Marshal(f)
}
