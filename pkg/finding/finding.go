// Package finding defines the [Finding] struct, the universal data model for
// security observations emitted by Trapline's scanner modules. Every scanner
// — whether it checks file integrity, open ports, running processes, or SSH
// keys — produces zero or more Finding values that flow through the system
// in a uniform way.
//
// Data flow:
//
//  1. A scanner module detects a deviation from baseline and constructs a
//     Finding with the appropriate severity, summary, and detail.
//  2. The scheduler collects findings and routes them to all enabled output
//     sinks (console, file, TCP, webhook) based on each sink's severity
//     threshold.
//  3. Output sinks serialize the Finding to JSON (via the json struct tags)
//     or render it as styled text (via the tui package).
//  4. The optional dashboard agent publishes findings to the central
//     dashboard for fleet-wide visibility.
//
// JSON serialization contract:
//
// The Finding struct's JSON field names (lowercase, snake_case via struct tags)
// form a stable API contract consumed by external systems: log aggregators,
// SIEM tools, the Trapline dashboard, and custom webhook integrations. Field
// names and types should not be changed without a version bump and migration
// path.
//
// Key JSON fields:
//
//	{
//	  "timestamp":        "2024-01-15T10:30:00Z",  // RFC 3339
//	  "hostname":         "web-01",
//	  "module":           "ports",
//	  "finding_id":       "ports:new-listener:tcp:0.0.0.0:4444",
//	  "severity":         "high",
//	  "status":           "new",
//	  "summary":          "New TCP listener on 0.0.0.0:4444",
//	  "detail":           { "port": 4444, "process": "nc" },
//	  "context":          { "baseline_count": 12 },
//	  "trapline_version": "0.4.2",
//	  "scan_id":          "a1b2c3d4"
//	}
package finding

import (
	"encoding/json"
	"time"
)

// Severity represents the severity level of a finding. The four levels form
// an ordered scale from informational observations to critical security events:
//
//   - SeverityInfo ("info"): informational observation that does not indicate
//     a security issue. Examples: a new non-privileged user was created, a
//     container image was updated. Typically only logged, not alerted.
//
//   - SeverityMedium ("medium"): a noteworthy change that may or may not be
//     malicious. Examples: a new cron job was added, a monitored file's
//     permissions changed. Worth investigating but not urgent.
//
//   - SeverityHigh ("high"): a change that is likely security-relevant and
//     warrants prompt attention. Examples: a new SUID binary appeared, a new
//     TCP listener on a non-standard port, an SSH authorized key was added.
//
//   - SeverityCritical ("critical"): a change that strongly indicates active
//     compromise or a critical security misconfiguration. Examples: rootkit
//     signatures detected, /etc/shadow was modified, a known-malicious
//     process is running.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityInfo     Severity = "info"
)

// Status represents the lifecycle status of a finding across successive scans.
// The scheduler tracks finding IDs between scans to determine transitions:
//
//   - StatusNew ("new"): this finding was not present in the previous scan.
//     It represents a freshly detected change.
//
//   - StatusRecurring ("recurring"): this finding was also present in the
//     previous scan and the condition persists. Output sinks may use cooldown
//     logic to suppress repeated alerts for recurring findings.
//
//   - StatusResolved ("resolved"): this finding was present in the previous
//     scan but is no longer detected. The condition has been remediated (or
//     the baseline was updated). A resolved finding is emitted once so that
//     downstream systems can close the corresponding alert.
type Status string

const (
	StatusNew       Status = "new"
	StatusRecurring Status = "recurring"
	StatusResolved  Status = "resolved"
)

// Finding represents a single security finding from a scanner module. It is
// the universal data model that flows through Trapline's entire pipeline:
// from scanner -> scheduler -> output sinks -> external systems.
//
// Findings are designed to be self-contained: each one includes enough context
// (hostname, module, timestamp, version, scan ID) to be meaningful in
// isolation, even when consumed by an external log aggregator that has no
// knowledge of Trapline's internal state.
type Finding struct {
	// Timestamp is when the finding was generated (typically time.Now() at
	// scan completion). Serialized as RFC 3339 in JSON.
	Timestamp time.Time `json:"timestamp"`

	// Hostname identifies the machine that produced this finding. Set from
	// the config's Hostname field or auto-detected from the OS.
	Hostname string `json:"hostname"`

	// Module is the name of the scanner module that produced this finding
	// (e.g. "ports", "file-integrity", "ssh"). Used for filtering and
	// grouping in dashboards and log queries.
	Module string `json:"module"`

	// FindingID is a deterministic, human-readable identifier that uniquely
	// identifies this specific finding within its module. The format is
	// module-specific but typically includes the module name and key
	// attributes, e.g. "ports:new-listener:tcp:0.0.0.0:4444". The scheduler
	// uses FindingID to track finding lifecycle (new -> recurring -> resolved)
	// across successive scans.
	FindingID string `json:"finding_id"`

	// Severity indicates the urgency and security relevance of this finding.
	// Output sinks filter findings by severity (e.g. webhook only fires for
	// "high" and above).
	Severity Severity `json:"severity"`

	// Status tracks the finding's lifecycle across scans. See [Status] for
	// the possible values and their meaning.
	Status Status `json:"status"`

	// Summary is a one-line human-readable description of the finding,
	// suitable for display in alerts and dashboards. Example: "New TCP
	// listener on 0.0.0.0:4444 (process: nc)".
	Summary string `json:"summary"`

	// Detail holds module-specific structured data about the finding. The
	// keys and value types are defined by each module (e.g. "port", "path",
	// "hash", "user"). This map is serialized to JSON and omitted when empty
	// (via the "omitempty" tag) to keep output clean for simple findings.
	Detail map[string]interface{} `json:"detail,omitempty"`

	// Context holds additional metadata that provides background for the
	// finding but is not part of the finding itself. Examples: baseline
	// counts, scan duration, module configuration. Omitted when empty.
	Context map[string]interface{} `json:"context,omitempty"`

	// TraplineVersion is the version of the Trapline binary that produced
	// this finding. Useful for debugging version-specific scanner behavior
	// in fleet-wide deployments.
	TraplineVersion string `json:"trapline_version"`

	// ScanID is a unique identifier for the scan execution that produced this
	// finding. All findings from the same scan share the same ScanID, which
	// allows correlating related findings and identifying which scan cycle
	// detected a change.
	ScanID string `json:"scan_id"`
}

// Level returns a numeric severity level for comparison and sorting. Higher
// values indicate more severe findings:
//
//	SeverityCritical -> 4
//	SeverityHigh     -> 3
//	SeverityMedium   -> 2
//	SeverityInfo     -> 1
//	unknown          -> 0
//
// This enables severity-based filtering (e.g. "only show findings with Level
// >= 3") and sorting (e.g. most severe first).
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

// ParseSeverity parses a severity string into a [Severity] constant. If the
// input does not match any known severity level (case-sensitive), it defaults
// to SeverityMedium. This default-to-medium strategy ensures that typos in
// configuration do not silently suppress findings — they are treated as
// medium severity rather than being ignored.
func ParseSeverity(s string) Severity {
	switch Severity(s) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityInfo:
		return Severity(s)
	default:
		return SeverityMedium
	}
}

// JSON returns the finding serialized as a JSON byte slice using the struct's
// json tags. This is the canonical serialization format used by file and TCP
// output sinks. The field names (snake_case) and types form a stable contract
// with external consumers.
func (f *Finding) JSON() ([]byte, error) {
	return json.Marshal(f)
}
