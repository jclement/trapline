package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/jclement/trapline/pkg/finding"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testFinding() *finding.Finding {
	return &finding.Finding{
		Module:    "file-integrity",
		FindingID: "file-modified:/etc/passwd",
		Severity:  finding.SeverityHigh,
		Status:    finding.StatusNew,
		Summary:   "/etc/passwd modified",
		Detail:    map[string]interface{}{"path": "/etc/passwd"},
	}
}

func TestOpenAndClose(t *testing.T) {
	s := testStore(t)
	if s == nil {
		t.Fatal("store is nil")
	}
}

func TestRecordFinding(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	hash, ignored, err := s.RecordFinding(f)
	if err != nil {
		t.Fatal(err)
	}
	if ignored {
		t.Error("new finding should not be ignored")
	}
	if len(hash) != 8 {
		t.Errorf("hash length = %d, want 8", len(hash))
	}
}

func TestHashIsStable(t *testing.T) {
	f := testFinding()
	h1 := HashFinding(f)
	h2 := HashFinding(f)
	if h1 != h2 {
		t.Errorf("hash not stable: %s != %s", h1, h2)
	}
}

func TestHashDiffersPerFinding(t *testing.T) {
	f1 := testFinding()
	f2 := &finding.Finding{Module: "ssh", FindingID: "ssh-config-changed"}
	if HashFinding(f1) == HashFinding(f2) {
		t.Error("different findings should have different hashes")
	}
}

func TestRecordUpdatesHitCount(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	_, _, _ = s.RecordFinding(f)
	_, _, _ = s.RecordFinding(f)
	_, _, _ = s.RecordFinding(f)

	findings, _ := s.ListFindings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].HitCount != 3 {
		t.Errorf("hit_count = %d, want 3", findings[0].HitCount)
	}
}

func TestIgnoreFinding(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	hash, _, _ := s.RecordFinding(f)
	if err := s.IgnoreFinding(hash, "known change"); err != nil {
		t.Fatal(err)
	}

	// Next record should be ignored
	_, ignored, _ := s.RecordFinding(f)
	if !ignored {
		t.Error("finding should be ignored after IgnoreFinding")
	}
}

func TestUnignoreFinding(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	hash, _, _ := s.RecordFinding(f)
	_ = s.IgnoreFinding(hash, "temp")
	_ = s.UnignoreFinding(hash)

	_, ignored, _ := s.RecordFinding(f)
	if ignored {
		t.Error("finding should not be ignored after UnignoreFinding")
	}
}

func TestUnignoreNonexistent(t *testing.T) {
	s := testStore(t)
	err := s.UnignoreFinding("deadbeef")
	if err == nil {
		t.Error("expected error for nonexistent ignore")
	}
}

func TestListIgnores(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	hash, _, _ := s.RecordFinding(f)
	_ = s.IgnoreFinding(hash, "approved change")

	ignores, err := s.ListIgnores()
	if err != nil {
		t.Fatal(err)
	}
	if len(ignores) != 1 {
		t.Fatalf("expected 1 ignore, got %d", len(ignores))
	}
	if ignores[0].Hash != hash {
		t.Errorf("hash = %s, want %s", ignores[0].Hash, hash)
	}
	if ignores[0].Reason != "approved change" {
		t.Errorf("reason = %q", ignores[0].Reason)
	}
}

func TestListFindings(t *testing.T) {
	s := testStore(t)

	_, _, _ = s.RecordFinding(testFinding())
	_, _, _ = s.RecordFinding(&finding.Finding{
		Module: "ssh", FindingID: "ssh-config-changed",
		Severity: finding.SeverityHigh, Summary: "ssh changed",
	})

	findings, err := s.ListFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
}

func TestIsIgnored(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	hash, _, _ := s.RecordFinding(f)
	if s.IsIgnored(hash) {
		t.Error("should not be ignored initially")
	}

	_ = s.IgnoreFinding(hash, "")
	if !s.IsIgnored(hash) {
		t.Error("should be ignored after IgnoreFinding")
	}
}

func TestPruneStaleIgnores(t *testing.T) {
	s := testStore(t)

	// Create an ignore that looks old
	_ = s.IgnoreFinding("oldone", "old")
	_, _ = s.db.Exec("UPDATE ignores SET created_at = ?, last_hit = NULL WHERE hash = ?",
		time.Now().Add(-90*24*time.Hour), "oldone")

	// Create a recent ignore
	_ = s.IgnoreFinding("newone", "new")

	pruned, err := s.PruneStaleIgnores(60 * 24 * time.Hour) // 60 days
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Errorf("pruned = %d, want 1", pruned)
	}

	// newone should still be there
	if !s.IsIgnored("newone") {
		t.Error("recent ignore should not be pruned")
	}
	if s.IsIgnored("oldone") {
		t.Error("old ignore should be pruned")
	}
}

func TestResolveStaleFindings(t *testing.T) {
	s := testStore(t)
	f := testFinding()
	_, _, _ = s.RecordFinding(f)

	// Make it look old
	_, _ = s.db.Exec("UPDATE findings SET last_seen = ?", time.Now().Add(-48*time.Hour))

	_ = s.ResolveStaleFindings(24 * time.Hour)

	findings, _ := s.ListFindings()
	if len(findings) != 0 {
		t.Errorf("expected 0 active findings after resolve, got %d", len(findings))
	}
}

func TestIgnoreTracksHits(t *testing.T) {
	s := testStore(t)
	f := testFinding()

	hash, _, _ := s.RecordFinding(f)
	_ = s.IgnoreFinding(hash, "known")

	// Hit the ignore multiple times
	_, _, _ = s.RecordFinding(f)
	_, _, _ = s.RecordFinding(f)

	ignores, _ := s.ListIgnores()
	if len(ignores) != 1 {
		t.Fatal("expected 1 ignore")
	}
	if ignores[0].HitCount != 2 {
		t.Errorf("hit_count = %d, want 2", ignores[0].HitCount)
	}
	if ignores[0].LastHit == nil {
		t.Error("last_hit should be set")
	}
}
