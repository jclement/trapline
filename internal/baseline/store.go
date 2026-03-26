// Package baseline provides JSON-on-disk persistence for scanner module
// baselines. A "baseline" is a snapshot of known-good system state (e.g. the
// set of listening ports, the SHA-256 hashes of monitored files, or the list
// of authorized SSH keys) captured during Trapline's learning mode or an
// explicit "trapline rebaseline" command. On each subsequent scan, a module
// loads its baseline, compares it to current system state, and emits findings
// for any differences.
//
// Persistence strategy:
//
//   - Each module gets a single JSON file named "<module>.json" inside the
//     baselines directory (typically /var/lib/trapline/baselines/).
//
//   - Writes use the atomic temp-file-then-rename pattern: data is first
//     written to "<module>.json.tmp", then renamed over the target. On Linux,
//     rename(2) on the same filesystem is atomic, so a crash or power loss
//     mid-write cannot leave a half-written baseline.
//
//   - File permissions are 0600 (owner read/write only) because baselines may
//     contain security-sensitive information such as file hashes, user lists,
//     or authorized keys.
//
// Thread safety:
//
//   - A single [sync.RWMutex] protects all operations. [Load] and [Exists]
//     take a read lock so multiple modules can read concurrently. [Save] and
//     [Delete] take an exclusive write lock.
//
//   - In practice, each module runs in its own goroutine on independent
//     intervals, so contention is minimal. The mutex primarily guards against
//     a rebaseline command running concurrently with a scheduled scan.
//
// Usage pattern for scanner modules:
//
//	// During scan:
//	var baseline PortBaseline
//	found, err := store.Load("ports", &baseline)
//	if !found {
//	    // First run — learn current state as the baseline.
//	    store.Save("ports", currentState)
//	    return nil
//	}
//	// Compare baseline to currentState and emit findings for differences.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store manages JSON baseline files on disk for scanner modules. It provides
// a simple key-value interface where the key is a module name (string) and the
// value is an arbitrary Go struct that is marshaled to/from JSON. All
// operations are safe for concurrent use from multiple goroutines.
type Store struct {
	// dir is the absolute path to the baselines directory on disk. Created
	// with mode 0700 in [NewStore] to ensure only root can access baseline
	// data.
	dir string

	// mu guards all filesystem operations. Read operations (Load, Exists)
	// take a read lock; write operations (Save, Delete) take an exclusive
	// write lock. This prevents a concurrent Save from corrupting a Load's
	// view of the file.
	mu sync.RWMutex
}

// NewStore creates a new baseline store rooted at the given directory. The
// directory is created with mode 0700 if it does not already exist. Returns
// an error if the directory cannot be created (e.g. permission denied).
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating baseline dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// path returns the absolute file path for a module's baseline JSON file. Each
// module's baseline is stored as a single file named "<module>.json" in the
// store's root directory. For example, the "ports" module's baseline lives at
// "<dir>/ports.json".
func (s *Store) path(module string) string {
	return filepath.Join(s.dir, module+".json")
}

// Load reads a module's baseline from disk and unmarshals the JSON into the
// provided value (which should be a pointer to the module's baseline struct).
//
// Return values:
//   - (true, nil): baseline existed and was successfully loaded into v.
//   - (false, nil): no baseline file exists for this module. This is the
//     expected case on first run or after a Delete. The caller should treat
//     current system state as the new baseline and call Save.
//   - (false, error): the file exists but could not be read or parsed. This
//     indicates corruption or a permissions problem.
//
// Load takes a read lock, so multiple modules can load their baselines
// concurrently without blocking each other.
func (s *Store) Load(module string, v interface{}) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path(module))
	if os.IsNotExist(err) {
		// No baseline on disk — this is the normal first-run case.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading baseline for %s: %w", module, err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("parsing baseline for %s: %w", module, err)
	}

	return true, nil
}

// Save writes a module's baseline to disk atomically. The value v is marshaled
// to indented JSON (for human readability when debugging) and written using
// the temp-file-then-rename pattern:
//
//  1. Marshal v to JSON with two-space indentation.
//  2. Write the JSON to "<module>.json.tmp" with mode 0600.
//  3. Rename the temp file over the final "<module>.json" path.
//
// Because rename(2) is atomic on the same filesystem, a crash at any point
// leaves either the old baseline intact or the new one fully written — never
// a partial file. If the rename fails, the temp file is cleaned up.
//
// Save takes an exclusive write lock to prevent concurrent reads from seeing
// a partially-renamed file.
func (s *Store) Save(module string, v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline for %s: %w", module, err)
	}

	// Write to temp file first, then rename for atomicity. The temp file
	// lives in the same directory to guarantee it is on the same filesystem
	// as the target, which is required for atomic rename(2).
	tmp := s.path(module) + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing baseline for %s: %w", module, err)
	}

	if err := os.Rename(tmp, s.path(module)); err != nil {
		// Clean up the orphaned temp file on rename failure.
		os.Remove(tmp)
		return fmt.Errorf("replacing baseline for %s: %w", module, err)
	}

	return nil
}

// Exists returns true if a baseline file exists on disk for the named module.
// This is a lightweight check (stat only, no read) used to determine whether
// a module has completed its initial learning phase. Takes a read lock.
func (s *Store) Exists(module string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := os.Stat(s.path(module))
	return err == nil
}

// Delete removes a module's baseline file from disk. After deletion, the next
// scan for that module will see no baseline (Load returns false) and re-learn
// current state. This is called by "trapline rebaseline --module <name>" to
// force a fresh baseline capture.
//
// Delete is idempotent: removing a non-existent baseline returns nil.
func (s *Store) Delete(module string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(module))
	if os.IsNotExist(err) {
		// Already absent — nothing to do. This makes Delete idempotent.
		return nil
	}
	return err
}

// Dir returns the absolute path to the baseline directory. This is exposed so
// that callers (e.g. the doctor health checks) can inspect or list the
// directory contents.
func (s *Store) Dir() string {
	return s.dir
}
