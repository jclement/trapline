package metrics

import (
	"testing"
	"time"
)

func TestRecord(t *testing.T) {
	c := New(100)
	c.Record("file-integrity", 50*time.Millisecond, 0)
	c.Record("file-integrity", 45*time.Millisecond, 1)
	c.Record("ports", 5*time.Millisecond, 2)

	summaries := c.Summary()
	if len(summaries) != 2 {
		t.Errorf("expected 2 modules, got %d", len(summaries))
	}
}

func TestSummaryAverages(t *testing.T) {
	c := New(100)
	c.Record("test", 100*time.Millisecond, 0)
	c.Record("test", 200*time.Millisecond, 0)
	c.Record("test", 300*time.Millisecond, 0)

	for _, s := range c.Summary() {
		if s.Module == "test" {
			if s.AvgDuration != 200*time.Millisecond {
				t.Errorf("avg = %v, want 200ms", s.AvgDuration)
			}
			if s.MaxDuration != 300*time.Millisecond {
				t.Errorf("max = %v, want 300ms", s.MaxDuration)
			}
			if s.ScanCount != 3 {
				t.Errorf("count = %d, want 3", s.ScanCount)
			}
			return
		}
	}
	t.Error("test module not found in summary")
}

func TestBoundedHistory(t *testing.T) {
	c := New(5) // small max
	for i := 0; i < 200; i++ {
		c.Record("test", time.Millisecond, 0)
	}
	// Should not grow unbounded
	c.mu.Lock()
	if len(c.history) > 100 {
		t.Errorf("history too large: %d", len(c.history))
	}
	c.mu.Unlock()
}

func TestFormatSummary(t *testing.T) {
	c := New(100)
	c.Record("file-integrity", 50*time.Millisecond, 0)
	c.Record("ports", 5*time.Millisecond, 2)

	out := c.FormatSummary()
	if out == "" {
		t.Error("expected non-empty summary")
	}
}

func TestEmptySummary(t *testing.T) {
	c := New(100)
	summaries := c.Summary()
	if len(summaries) != 0 {
		t.Errorf("expected 0 summaries, got %d", len(summaries))
	}
}
