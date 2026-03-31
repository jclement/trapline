// Package store provides a persistent SQLite-backed store for security findings
// and user-managed ignore rules in Trapline.
//
// # Schema Design
//
// The database consists of two tables:
//
//   - findings: Tracks every security finding discovered by scan modules.
//     Each row is keyed by an 8-character hex hash derived from the module name
//     and finding ID (see [HashFinding]). Rows record severity, summary, detail,
//     first/last seen timestamps, a hit count (incremented on every re-observation),
//     and a status field ("active" or "resolved").
//
//   - ignores: Tracks user-suppressed findings. Keyed by the same 8-char hex hash
//     so that a finding and its ignore rule share a single identifier. Stores the
//     original module, finding ID, a human-supplied reason, creation time, the
//     timestamp of the most recent hit (last_hit), and a hit count showing how
//     many times the suppressed finding has been re-observed since being ignored.
//
// # Hash-Based Finding IDs
//
// Every finding is identified by an 8-character hexadecimal string computed as
// SHA-256(module + ":" + finding_id) truncated to 4 bytes. This gives a compact,
// deterministic identifier that is stable across runs -- the same module+finding_id
// always produces the same hash. Users reference these short hashes in CLI commands
// such as "trapline ignore <hash>". See [HashFinding] for collision analysis.
//
// # Ignore Workflow
//
// The ignore lifecycle works as follows:
//
//  1. A user runs "trapline ignore <hash> --reason '...'" to suppress a finding.
//     [Store.IgnoreFinding] inserts a row into the ignores table. If the hash
//     corresponds to an existing finding, the module/finding_id/summary are copied
//     over for display purposes; otherwise the ignore is still created with
//     placeholder metadata (allowing pre-emptive ignores).
//
//  2. On subsequent scans, [Store.RecordFinding] checks the ignores table first.
//     If the hash is present, the finding is not recorded (or re-activated) in the
//     findings table; instead the ignore's last_hit and hit_count are bumped so
//     operators can see that the suppressed issue is still being detected.
//
//  3. A user can reverse an ignore with "trapline unignore <hash>", which calls
//     [Store.UnignoreFinding] to delete the row.
//
//  4. Stale ignores -- those whose last_hit (or created_at, if never hit) exceeds
//     60 days -- are automatically pruned by [Store.PruneStaleIgnores]. This
//     prevents the ignore list from accumulating rules for findings that no longer
//     appear, keeping the suppress list relevant.
//
// # Hit Count Tracking
//
// Both tables maintain a hit_count column:
//
//   - In findings, hit_count records how many scan cycles have observed the finding.
//     It starts at 1 on first insert and increments on every subsequent upsert.
//
//   - In ignores, hit_count records how many times the suppressed finding has been
//     re-detected since being ignored. It starts at 0 and increments each time
//     [Store.RecordFinding] encounters an ignored hash. A high hit_count on an
//     ignore signals that the underlying issue persists and may deserve attention.
//
// # WAL Mode and Concurrency
//
// The database is opened with "?_journal_mode=WAL" (Write-Ahead Logging). WAL mode
// allows concurrent readers and a single writer without blocking, which is important
// because scan modules may run in parallel goroutines that all call RecordFinding
// concurrently. WAL also improves write performance by batching journal flushes.
//
// # Stale Finding Resolution
//
// Findings that have not been observed for a configurable duration are marked as
// "resolved" by [Store.ResolveStaleFindings]. This happens by updating the status
// column from "active" to "resolved" for any row whose last_seen is older than the
// cutoff. Resolved findings are excluded from [Store.ListFindings] but remain in the
// database for historical reference. If a resolved finding reappears in a future
// scan, the upsert in [Store.RecordFinding] flips its status back to "active".
package store

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	// modernc.org/sqlite is a pure-Go (CGO_ENABLED=0 compatible) SQLite driver.
	// It registers itself under the driver name "sqlite".
	_ "modernc.org/sqlite"

	"github.com/jclement/trapline/pkg/finding"
)

// Store manages findings and ignores in SQLite.
// All methods are safe for concurrent use because SQLite in WAL mode serializes
// writes internally and the database/sql connection pool handles concurrency at
// the Go level.
type Store struct {
	db *sql.DB
}

// Open opens or creates the SQLite database at the given path.
// The directory is created with mode 0700 (owner-only) if it does not exist,
// since the database may contain sensitive security finding details.
// The database file is named "trapline.db" inside dir.
// WAL journal mode is enabled via the connection string to allow concurrent
// readers without blocking writers, which is critical when multiple scan
// modules record findings in parallel.
// After opening, migrate is called to ensure the schema is up to date.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "trapline.db")
	// The "?_journal_mode=WAL" pragma is set via the DSN so it takes effect
	// before any other operations. WAL (Write-Ahead Logging) mode allows
	// multiple concurrent readers alongside a single writer, which is
	// important because scan modules may call RecordFinding in parallel.
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	return &Store{db: db}, nil
}

// migrate creates the schema if it does not already exist.
//
// Schema design decisions:
//
//   - findings.hash (TEXT PRIMARY KEY): The 8-char hex hash is the natural key.
//     Using it as the primary key avoids an extra integer rowid and makes lookups
//     by hash (the most common access pattern) a direct index seek.
//
//   - findings.status: A text field ("active" / "resolved") rather than a boolean
//     so it can be extended to other states (e.g. "acknowledged") in the future.
//     Defaults to "active" on insert.
//
//   - findings.hit_count: Starts at 1 (the first observation counts as a hit).
//     Incremented on every upsert via ON CONFLICT ... hit_count + 1.
//
//   - ignores.hash (TEXT PRIMARY KEY): Same hash space as findings, so a single
//     hash value identifies both the finding and its ignore rule.
//
//   - ignores.last_hit: Nullable -- NULL means the ignore has never been hit
//     since creation. PruneStaleIgnores uses created_at as the fallback when
//     last_hit IS NULL, so newly-created ignores that are never triggered will
//     still be pruned after the expiry window.
//
//   - ignores.hit_count: Starts at 0 (unlike findings which start at 1) because
//     creating an ignore is not the same as observing the finding.
//
//   - Indexes: idx_findings_module speeds up per-module queries (e.g. "show me
//     all findings from the ssl_cert module"). idx_findings_status speeds up
//     ListFindings which filters on status='active'. idx_ignores_last_hit speeds
//     up PruneStaleIgnores which scans by last_hit timestamp.
//
// All statements use CREATE TABLE/INDEX IF NOT EXISTS so the migration is
// idempotent and safe to run on every startup.
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

// HashFinding computes a stable, deterministic 8-character hexadecimal identifier
// for a finding by hashing module + ":" + finding_id with SHA-256 and truncating
// to the first 4 bytes.
//
// Why 4 bytes (8 hex characters)?
//
// 4 bytes gives 2^32 (~4.3 billion) possible values. By the birthday paradox,
// the probability of at least one collision reaches 50% at ~65,536 findings
// (sqrt(2^32)). In practice Trapline tracks tens to low hundreds of findings
// per deployment, so the collision probability is negligible (roughly 1 in
// 1,000,000 for 100 findings). The 8-char hex string is short enough to be
// comfortable in CLI output and copy-paste workflows ("trapline ignore a1b2c3d4")
// while remaining unique for any realistic finding set.
//
// The hash is computed over module + ":" + finding_id only (not severity, summary,
// or detail) so that the identifier remains stable even when a module updates its
// description text across versions. This stability is essential for the ignore
// workflow: an ignore rule created in one scan run must still match the same
// finding in future runs.
func HashFinding(f *finding.Finding) string {
	data := f.Module + ":" + f.FindingID
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:4]) // 8-char hex hash
}

// RecordFinding records or updates a finding in the database.
// Returns the hash, whether the finding is currently ignored, and any error.
//
// The flow is:
//
//  1. Compute the finding's hash via [HashFinding].
//
//  2. Check the ignores table. If a matching row exists, the finding is
//     suppressed: bump the ignore's last_hit and hit_count so operators can
//     see that the underlying issue persists, then return (hash, true, nil)
//     without touching the findings table at all. This means ignored findings
//     do not appear in ListFindings output.
//
//  3. If not ignored, serialize the Detail map to a simple "key=value; " string
//     for storage (Detail is supplementary and not used for identification).
//
//  4. Upsert into the findings table using INSERT ... ON CONFLICT(hash) DO UPDATE.
//     On first observation, all columns take their inserted values (hit_count
//     defaults to 1). On subsequent observations, only last_seen, hit_count,
//     severity, summary, and status are updated. Notably, status is reset to
//     "active" on every upsert -- this is how a previously-resolved finding is
//     automatically reactivated if it reappears in a future scan. first_seen
//     and detail are NOT updated on conflict, preserving the original discovery
//     time and initial detail snapshot.
func (s *Store) RecordFinding(f *finding.Finding) (hash string, ignored bool, err error) {
	hash = HashFinding(f)

	// Check if this finding's hash exists in the ignores table.
	// If it does, we skip recording the finding entirely and instead
	// update the ignore's tracking fields so the user can see that the
	// suppressed issue is still being detected.
	var ignoreHash string
	err = s.db.QueryRow("SELECT hash FROM ignores WHERE hash = ?", hash).Scan(&ignoreHash)
	if err == nil {
		// Update ignore hit tracking: bump last_hit to now and increment
		// hit_count. These fields power PruneStaleIgnores (last_hit) and
		// the "trapline ignores" display (hit_count).
		_, _ = s.db.Exec("UPDATE ignores SET last_hit = CURRENT_TIMESTAMP, hit_count = hit_count + 1 WHERE hash = ?", hash)
		return hash, true, nil
	}
	// If err is sql.ErrNoRows, the finding is not ignored -- proceed to record it.
	// Any other error from QueryRow.Scan would also land here, but for a simple
	// existence check the only expected "error" is ErrNoRows.

	// Serialize the Detail map into a flat string for the TEXT column.
	// This is intentionally lossy -- Detail is supplementary context (e.g.,
	// IP addresses, certificate expiry dates) and is not used for finding
	// identification or deduplication.
	detailStr := ""
	if f.Detail != nil {
		// Simple key=value serialization
		for k, v := range f.Detail {
			detailStr += fmt.Sprintf("%s=%v; ", k, v)
		}
	}

	// Upsert the finding. INSERT creates a new row if the hash is novel.
	// ON CONFLICT(hash) fires when this finding has been seen before, updating:
	//   - last_seen: moved to now so ResolveStaleFindings knows it is fresh
	//   - hit_count: incremented to track observation frequency
	//   - severity/summary: updated to the latest values in case the module
	//     changed its assessment (e.g., severity escalated from low to high)
	//   - status: forced back to "active" -- this is the mechanism that
	//     reactivates a previously-resolved finding when it recurs
	// Fields NOT updated on conflict: first_seen (preserves discovery date),
	// detail (preserves the initial detail snapshot), module, finding_id (these
	// are part of the hash derivation and cannot change for the same hash).
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

// IgnoreFinding adds a finding hash to the ignore list with an optional reason.
//
// If the hash corresponds to an existing row in the findings table, the module,
// finding_id, and summary are copied into the ignores row for display purposes
// (so "trapline ignores" can show meaningful context even without joining).
//
// If the hash does NOT correspond to a known finding -- for example, the user
// is pre-emptively ignoring a finding they expect to see -- placeholder values
// are used ("unknown" module, hash as finding_id, "manually ignored" summary).
// This allows proactive suppression before a finding is ever recorded.
//
// INSERT OR REPLACE is used so that re-ignoring an already-ignored hash updates
// the reason and resets created_at, last_hit, and hit_count to their defaults.
func (s *Store) IgnoreFinding(hash, reason string) error {
	// Attempt to look up the finding's metadata for richer ignore display.
	var module, findingID, summary string
	err := s.db.QueryRow("SELECT module, finding_id, summary FROM findings WHERE hash = ?", hash).
		Scan(&module, &findingID, &summary)
	if err != nil {
		// Allow ignoring by hash even without a recorded finding.
		// This supports proactive ignores and ignoring findings that
		// were already resolved/pruned from the findings table.
		module = "unknown"
		findingID = hash
		summary = "manually ignored"
	}

	// INSERT OR REPLACE: if the hash already exists in ignores, the entire
	// row is replaced. This effectively "re-ignores" with a fresh timestamp
	// and zeroed hit_count, which is the desired behavior when a user updates
	// the reason for an existing ignore.
	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO ignores (hash, module, finding_id, summary, reason)
		VALUES (?, ?, ?, ?, ?)
	`, hash, module, findingID, summary, reason)
	return err
}

// UnignoreFinding removes a hash from the ignore list, re-enabling detection
// alerts for that finding in future scans.
// Returns an error if no ignore exists with the given hash, so the user gets
// clear feedback rather than a silent no-op.
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

// IgnoreEntry represents an ignored finding as stored in the ignores table.
// It carries all columns so that CLI display commands can render full context
// without a second query.
type IgnoreEntry struct {
	Hash      string     // 8-char hex finding hash (primary key, same as findings.hash)
	Module    string     // Module name that produced the finding (or "unknown")
	FindingID string     // Module-specific finding identifier (or the hash itself)
	Summary   string     // Human-readable summary of the finding
	Reason    string     // User-supplied reason for ignoring
	CreatedAt time.Time  // When the ignore was created
	LastHit   *time.Time // Last time a scan matched this ignore (nil if never hit)
	HitCount  int        // Number of times the finding was re-detected while ignored
}

// ListIgnores returns all ignored findings, ordered by creation time (newest first).
// The full IgnoreEntry is returned so callers can display hit_count and last_hit
// to help users assess whether an ignore is still relevant.
func (s *Store) ListIgnores() ([]IgnoreEntry, error) {
	rows, err := s.db.Query(`
		SELECT hash, module, finding_id, summary, reason, created_at, last_hit, hit_count
		FROM ignores ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ignores []IgnoreEntry
	for rows.Next() {
		var e IgnoreEntry
		// last_hit is nullable (NULL when the ignore has never been triggered),
		// so we scan into sql.NullTime and convert to *time.Time.
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

// FindingEntry represents a recorded finding as stored in the findings table.
// All columns are exposed so CLI commands can render detailed finding information.
type FindingEntry struct {
	Hash      string    // 8-char hex finding hash (primary key)
	Module    string    // Module that produced this finding (e.g. "ssl_cert", "dns")
	FindingID string    // Module-specific finding identifier
	Severity  string    // Severity level (critical, high, medium, low, info)
	Summary   string    // One-line human-readable summary
	Detail    string    // Serialized key=value detail string (may be empty)
	FirstSeen time.Time // When this finding was first observed
	LastSeen  time.Time // When this finding was most recently observed
	HitCount  int       // Total number of times this finding has been observed
	Status    string    // "active" or "resolved"
}

// ListFindings returns all active findings, ordered by last_seen (most recent first).
// Resolved findings are excluded from the result set. They remain in the database
// for historical reference and can be reactivated by RecordFinding if the issue
// recurs.
func (s *Store) ListFindings() ([]FindingEntry, error) {
	rows, err := s.db.Query(`
		SELECT hash, module, finding_id, severity, summary, detail, first_seen, last_seen, hit_count, status
		FROM findings WHERE status = 'active' ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

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
// This is a lightweight existence check (SELECT hash only) used by callers
// that need a quick boolean answer without updating the ignore's hit tracking.
// Note: RecordFinding has its own inline ignore check that also bumps hit_count;
// this method is for read-only checks outside the recording flow.
func (s *Store) IsIgnored(hash string) bool {
	var h string
	err := s.db.QueryRow("SELECT hash FROM ignores WHERE hash = ?", hash).Scan(&h)
	return err == nil
}

// PruneStaleIgnores removes ignores that haven't been triggered in the given
// duration (typically 60 days).
//
// The 60-day expiry design rationale: ignore rules should not live forever because
// the underlying infrastructure and threat landscape change. If an ignored finding
// has not been re-detected in 60 days, it likely no longer applies (the issue was
// fixed, the asset was decommissioned, etc.). Pruning keeps the ignore list lean
// and forces periodic human review of long-lived suppressions.
//
// Deletion criteria:
//   - If last_hit IS NOT NULL (the ignore has been triggered at least once):
//     delete if last_hit is older than the cutoff. This means the finding was
//     seen at some point but has since stopped appearing.
//   - If last_hit IS NULL (the ignore was created but never triggered):
//     delete if created_at is older than the cutoff. This catches "stale"
//     pre-emptive ignores that were set up but never matched any finding.
//
// Returns the number of pruned rows so callers can log/report the cleanup.
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

// ResolveStaleFindings marks findings as "resolved" if they haven't been seen
// within maxAge. This is the counterpart to the upsert in RecordFinding which
// flips status back to "active" on re-observation. Together they implement
// automatic lifecycle management:
//
//   - A finding starts as "active" when first recorded.
//   - If it is not re-observed within maxAge, it transitions to "resolved".
//   - If it reappears later, RecordFinding's ON CONFLICT clause sets status
//     back to "active", restarting the cycle.
//
// Only findings with status='active' are candidates for resolution. Already-
// resolved findings are left untouched (their last_seen timestamp is preserved
// as a historical record of when they were last observed).
func (s *Store) ResolveStaleFindings(maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge)
	_, err := s.db.Exec("UPDATE findings SET status = 'resolved' WHERE last_seen < ? AND status = 'active'", cutoff)
	return err
}

// Close closes the underlying database connection, flushing any WAL data
// and releasing file locks. Should be called when the store is no longer needed,
// typically via defer after Open.
func (s *Store) Close() error {
	return s.db.Close()
}
