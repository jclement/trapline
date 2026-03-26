package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jclement/tripline/pkg/finding"
)

// Store manages findings and ignores in SQLite.
type Store struct {
	db *sql.DB
}

// Open opens or creates the SQLite database at the given path.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "trapline.db")
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			hash TEXT PRIMARY KEY,
			module TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			summary TEXT NOT NULL,
			detail TEXT,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			hit_count INTEGER NOT NULL DEFAULT 1,
			status TEXT NOT NULL DEFAULT 'active'
		);

		CREATE TABLE IF NOT EXISTS ignores (
			hash TEXT PRIMARY KEY,
			module TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			summary TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_hit DATETIME,
			hit_count INTEGER NOT NULL DEFAULT 0
		);

		CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module);
		CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
		CREATE INDEX IF NOT EXISTS idx_ignores_last_hit ON ignores(last_hit);
	`)
	return err
}

// HashFinding computes a stable hash for a finding (module + finding_id).
// This is the short ID users see and use with `trapline ignore`.
func HashFinding(f *finding.Finding) string {
	data := f.Module + ":" + f.FindingID
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:4]) // 8-char hex hash
}

// RecordFinding records or updates a finding in the database.
// Returns the hash and whether the finding is ignored.
func (s *Store) RecordFinding(f *finding.Finding) (hash string, ignored bool, err error) {
	hash = HashFinding(f)

	// Check if ignored
	var ignoreHash string
	err = s.db.QueryRow("SELECT hash FROM ignores WHERE hash = ?", hash).Scan(&ignoreHash)
	if err == nil {
		// Update ignore hit tracking
		s.db.Exec("UPDATE ignores SET last_hit = CURRENT_TIMESTAMP, hit_count = hit_count + 1 WHERE hash = ?", hash)
		return hash, true, nil
	}

	// Serialize detail
	detailStr := ""
	if f.Detail != nil {
		// Simple key=value serialization
		for k, v := range f.Detail {
			detailStr += fmt.Sprintf("%s=%v; ", k, v)
		}
	}

	// Upsert finding
	_, err = s.db.Exec(`
		INSERT INTO findings (hash, module, finding_id, severity, summary, detail)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(hash) DO UPDATE SET
			last_seen = CURRENT_TIMESTAMP,
			hit_count = hit_count + 1,
			severity = excluded.severity,
			summary = excluded.summary,
			status = 'active'
	`, hash, f.Module, f.FindingID, string(f.Severity), f.Summary, detailStr)

	return hash, false, err
}

// IgnoreFinding adds a finding hash to the ignore list.
func (s *Store) IgnoreFinding(hash, reason string) error {
	// Get finding info if it exists
	var module, findingID, summary string
	err := s.db.QueryRow("SELECT module, finding_id, summary FROM findings WHERE hash = ?", hash).
		Scan(&module, &findingID, &summary)
	if err != nil {
		// Allow ignoring by hash even without a recorded finding
		module = "unknown"
		findingID = hash
		summary = "manually ignored"
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO ignores (hash, module, finding_id, summary, reason)
		VALUES (?, ?, ?, ?, ?)
	`, hash, module, findingID, summary, reason)
	return err
}

// UnignoreFinding removes a hash from the ignore list.
func (s *Store) UnignoreFinding(hash string) error {
	result, err := s.db.Exec("DELETE FROM ignores WHERE hash = ?", hash)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("no ignore found with hash %s", hash)
	}
	return nil
}

// IgnoreEntry represents an ignored finding.
type IgnoreEntry struct {
	Hash      string
	Module    string
	FindingID string
	Summary   string
	Reason    string
	CreatedAt time.Time
	LastHit   *time.Time
	HitCount  int
}

// ListIgnores returns all ignored findings.
func (s *Store) ListIgnores() ([]IgnoreEntry, error) {
	rows, err := s.db.Query(`
		SELECT hash, module, finding_id, summary, reason, created_at, last_hit, hit_count
		FROM ignores ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ignores []IgnoreEntry
	for rows.Next() {
		var e IgnoreEntry
		var lastHit sql.NullTime
		if err := rows.Scan(&e.Hash, &e.Module, &e.FindingID, &e.Summary, &e.Reason, &e.CreatedAt, &lastHit, &e.HitCount); err != nil {
			return nil, err
		}
		if lastHit.Valid {
			e.LastHit = &lastHit.Time
		}
		ignores = append(ignores, e)
	}
	return ignores, rows.Err()
}

// FindingEntry represents a recorded finding.
type FindingEntry struct {
	Hash      string
	Module    string
	FindingID string
	Severity  string
	Summary   string
	Detail    string
	FirstSeen time.Time
	LastSeen  time.Time
	HitCount  int
	Status    string
}

// ListFindings returns active findings.
func (s *Store) ListFindings() ([]FindingEntry, error) {
	rows, err := s.db.Query(`
		SELECT hash, module, finding_id, severity, summary, detail, first_seen, last_seen, hit_count, status
		FROM findings WHERE status = 'active' ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []FindingEntry
	for rows.Next() {
		var e FindingEntry
		if err := rows.Scan(&e.Hash, &e.Module, &e.FindingID, &e.Severity, &e.Summary, &e.Detail, &e.FirstSeen, &e.LastSeen, &e.HitCount, &e.Status); err != nil {
			return nil, err
		}
		findings = append(findings, e)
	}
	return findings, rows.Err()
}

// IsIgnored checks if a finding hash is in the ignore list.
func (s *Store) IsIgnored(hash string) bool {
	var h string
	err := s.db.QueryRow("SELECT hash FROM ignores WHERE hash = ?", hash).Scan(&h)
	return err == nil
}

// PruneStaleIgnores removes ignores that haven't been triggered in the given duration.
func (s *Store) PruneStaleIgnores(maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)
	result, err := s.db.Exec(`
		DELETE FROM ignores
		WHERE (last_hit IS NOT NULL AND last_hit < ?)
		   OR (last_hit IS NULL AND created_at < ?)
	`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	rows, _ := result.RowsAffected()
	return int(rows), nil
}

// ResolveStaleFindings marks findings as resolved if they haven't been seen recently.
func (s *Store) ResolveStaleFindings(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)
	_, err := s.db.Exec("UPDATE findings SET status = 'resolved' WHERE last_seen < ? AND status = 'active'", cutoff)
	return err
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}
