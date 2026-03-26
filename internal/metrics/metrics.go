package metrics

import (
	"fmt"
	"sync"
	"time"
)

// ScanMetric records timing for a single module scan.
type ScanMetric struct {
	Module    string        `json:"module"`
	Duration  time.Duration `json:"duration_ms"`
	Findings  int           `json:"findings"`
	Timestamp time.Time     `json:"timestamp"`
}

// Collector accumulates scan metrics.
type Collector struct {
	mu      sync.Mutex
	history []ScanMetric // last N entries per module
	maxHist int
}

// New creates a collector that keeps the last maxPerModule entries per module.
func New(maxPerModule int) *Collector {
	return &Collector{maxHist: maxPerModule}
}

// Record adds a scan metric.
func (c *Collector) Record(module string, duration time.Duration, findingCount int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history = append(c.history, ScanMetric{
		Module:    module,
		Duration:  duration,
		Findings:  findingCount,
		Timestamp: time.Now(),
	})
	// Keep bounded
	if len(c.history) > c.maxHist*20 { // rough cap
		c.history = c.history[len(c.history)-c.maxHist*10:]
	}
}

// ModuleSummary returns the latest metric and average duration per module.
type ModuleSummary struct {
	Module       string        `json:"module"`
	LastDuration time.Duration `json:"last_duration_ms"`
	AvgDuration  time.Duration `json:"avg_duration_ms"`
	MaxDuration  time.Duration `json:"max_duration_ms"`
	LastFindings int           `json:"last_findings"`
	ScanCount    int           `json:"scan_count"`
}

// Summary returns per-module summaries.
func (c *Collector) Summary() []ModuleSummary {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Group by module
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
		var total time.Duration
		for _, m := range metrics {
			total += m.Duration
			if m.Duration > s.MaxDuration {
				s.MaxDuration = m.Duration
			}
		}
		s.AvgDuration = total / time.Duration(len(metrics))
		last := metrics[len(metrics)-1]
		s.LastDuration = last.Duration
		s.LastFindings = last.Findings
		summaries = append(summaries, s)
	}
	return summaries
}

// FormatSummary returns a human-readable string of all module metrics.
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
