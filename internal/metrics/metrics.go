// Package metrics provides a lightweight, in-memory scan-timing collector for
// Trapline's scanner modules. Each time a module completes a scan, the
// scheduler records the module name, scan duration, and number of findings.
// This data powers the "trapline status" display and can be exposed via the
// dashboard agent for fleet-wide performance monitoring.
//
// Design:
//
//   - Per-module timing: every [Record] call appends a [ScanMetric] entry to a
//     shared history slice. The collector does not maintain per-module slices;
//     instead, [Summary] groups the flat history by module name at query time.
//
//   - Bounded history: to prevent unbounded memory growth in long-running
//     daemons, the history is pruned when it exceeds maxHist*20 entries by
//     dropping the oldest half. The "*20" factor accounts for the fact that
//     the history is shared across all modules (typically ~13), so each module
//     retains roughly maxHist entries on average.
//
//   - Thread safety: a single [sync.Mutex] protects all reads and writes.
//     Contention is negligible because Record is called at most once per
//     module per scan interval (seconds to minutes), and Summary is called
//     only for status display.
//
//   - No persistence: metrics are purely in-memory and reset on process
//     restart. Historical data is not needed across restarts because the
//     primary use case is live operational monitoring.
package metrics

import (
	"fmt"
	"sync"
	"time"
)

// ScanMetric records the timing and result count for a single module scan
// execution. These entries are the raw data collected by [Collector.Record]
// and aggregated by [Collector.Summary].
type ScanMetric struct {
	// Module is the name of the scanner module (e.g. "ports", "file-integrity").
	Module string `json:"module"`

	// Duration is how long the scan took to execute. Serialized as
	// "duration_ms" in JSON for dashboard consumption.
	Duration time.Duration `json:"duration_ms"`

	// Findings is the number of findings emitted by this scan execution.
	Findings int `json:"findings"`

	// Timestamp is when the scan completed (set to time.Now() in Record).
	Timestamp time.Time `json:"timestamp"`
}

// Collector accumulates scan metrics in a bounded in-memory history. It is
// safe for concurrent use by multiple scanner goroutines. Create one with
// [New] and share it across the application.
type Collector struct {
	// mu protects all access to the history slice. A full Mutex (not RWMutex)
	// is used because even Summary needs to iterate the slice under a lock,
	// and the critical sections are short enough that reader/writer
	// distinction provides no meaningful benefit.
	mu sync.Mutex

	// history is the append-only (with periodic pruning) list of scan metrics
	// across all modules. Entries are in chronological order because Record
	// always appends.
	history []ScanMetric

	// maxHist is the per-module history target passed to New. The actual
	// pruning threshold is maxHist*20 (shared across ~13 modules), and
	// pruning retains maxHist*10 entries.
	maxHist int
}

// New creates a Collector that targets keeping approximately maxPerModule
// history entries per module. The actual capacity is maxPerModule * 20 across
// all modules (to account for ~13 built-in modules), pruned to maxPerModule *
// 10 when the threshold is exceeded.
//
// A typical value is 100, which retains the last ~100 scans per module —
// enough to compute meaningful averages without significant memory overhead.
func New(maxPerModule int) *Collector {
	return &Collector{maxHist: maxPerModule}
}

// Record adds a scan metric for the named module. This is called by the
// scheduler after each module scan completes. The timestamp is set to
// time.Now() automatically.
//
// If the total history length exceeds the pruning threshold (maxHist * 20),
// the oldest entries are dropped to bring the length down to maxHist * 10.
// This is a simple but effective strategy: rather than tracking per-module
// counts, we prune the shared history globally. Because modules scan at
// different intervals, faster modules contribute more entries, but the
// overall memory is still bounded.
func (c *Collector) Record(module string, duration time.Duration, findingCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history = append(c.history, ScanMetric{
		Module:    module,
		Duration:  duration,
		Findings:  findingCount,
		Timestamp: time.Now(),
	})
	// Prune when the history grows beyond the rough cap. The factor of 20
	// gives headroom for ~13 modules each contributing ~1.5x their target
	// history. Pruning retains the newest half (maxHist*10 entries).
	if len(c.history) > c.maxHist*20 {
		c.history = c.history[len(c.history)-c.maxHist*10:]
	}
}

// ModuleSummary holds aggregated metrics for a single module, computed from
// the raw history by [Collector.Summary]. It provides the last scan's timing
// and findings, plus statistical aggregates (average and max duration) across
// all retained history for that module.
type ModuleSummary struct {
	// Module is the scanner module name.
	Module string `json:"module"`

	// LastDuration is the duration of the most recent scan for this module.
	LastDuration time.Duration `json:"last_duration_ms"`

	// AvgDuration is the arithmetic mean of all retained scan durations for
	// this module.
	AvgDuration time.Duration `json:"avg_duration_ms"`

	// MaxDuration is the longest scan duration observed in the retained
	// history for this module. Useful for identifying occasional slow scans.
	MaxDuration time.Duration `json:"max_duration_ms"`

	// LastFindings is the number of findings from the most recent scan.
	LastFindings int `json:"last_findings"`

	// ScanCount is the total number of retained scan entries for this module.
	ScanCount int `json:"scan_count"`
}

// Summary computes per-module aggregated metrics from the raw history. It
// groups all retained ScanMetric entries by module name, then for each module
// calculates:
//
//   - LastDuration: duration of the chronologically last entry
//   - AvgDuration: arithmetic mean of all durations (total / count)
//   - MaxDuration: maximum duration across all entries
//   - LastFindings: finding count from the last entry
//   - ScanCount: total number of entries
//
// The returned slice is unordered (map iteration order). Callers that need
// sorted output should sort the result themselves.
func (c *Collector) Summary() []ModuleSummary {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Group raw metrics by module name. Each module gets its own slice of
	// ScanMetric entries in chronological order (preserved from the append-
	// only history).
	byModule := make(map[string][]ScanMetric)
	for _, m := range c.history {
		byModule[m.Module] = append(byModule[m.Module], m)
	}

	var summaries []ModuleSummary
	for mod, metrics := range byModule {
		s := ModuleSummary{
			Module:    mod,
			ScanCount: len(metrics),
		}
		// Compute total and max duration in a single pass over the module's
		// history.
		var total time.Duration
		for _, m := range metrics {
			total += m.Duration
			if m.Duration > s.MaxDuration {
				s.MaxDuration = m.Duration
			}
		}
		// Arithmetic mean: total duration divided by number of scans.
		s.AvgDuration = total / time.Duration(len(metrics))
		// The last element is the most recent scan (history is append-only).
		last := metrics[len(metrics)-1]
		s.LastDuration = last.Duration
		s.LastFindings = last.Findings
		summaries = append(summaries, s)
	}
	return summaries
}

// FormatSummary returns a human-readable multi-line string of all module
// metrics, suitable for display in "trapline status" output. Each line shows
// the module name (left-aligned, 20 chars), last/avg/max durations rounded to
// milliseconds, total scan count, and the most recent finding count. Example:
//
//	ports                last=  12ms  avg=  11ms  max=  45ms  scans=42  findings=0
//	file-integrity       last= 340ms  avg= 312ms  max= 890ms  scans=8   findings=2
func (c *Collector) FormatSummary() string {
	summaries := c.Summary()
	result := ""
	for _, s := range summaries {
		result += fmt.Sprintf("  %-20s last=%6s  avg=%6s  max=%6s  scans=%d  findings=%d\n",
			s.Module,
			s.LastDuration.Round(time.Millisecond),
			s.AvgDuration.Round(time.Millisecond),
			s.MaxDuration.Round(time.Millisecond),
			s.ScanCount,
			s.LastFindings,
		)
	}
	return result
}
