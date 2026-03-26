package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store manages JSON baseline files on disk for scanner modules.
type Store struct {
	dir string
	mu  sync.RWMutex
}

// NewStore creates a new baseline store at the given directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating baseline dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// path returns the file path for a module's baseline.
func (s *Store) path(module string) string {
	return filepath.Join(s.dir, module+".json")
}

// Load reads a module's baseline into the provided value.
// Returns false if no baseline exists (first run).
func (s *Store) Load(module string, v interface{}) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path(module))
	if os.IsNotExist(err) {
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

// Save writes a module's baseline to disk atomically.
func (s *Store) Save(module string, v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling baseline for %s: %w", module, err)
	}

	// Write to temp file first, then rename for atomicity
	tmp := s.path(module) + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing baseline for %s: %w", module, err)
	}

	if err := os.Rename(tmp, s.path(module)); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing baseline for %s: %w", module, err)
	}

	return nil
}

// Exists returns true if a baseline exists for the module.
func (s *Store) Exists(module string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := os.Stat(s.path(module))
	return err == nil
}

// Delete removes a module's baseline.
func (s *Store) Delete(module string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(module))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Dir returns the baseline directory path.
func (s *Store) Dir() string {
	return s.dir
}
