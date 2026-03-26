package baseline

import (
	"path/filepath"
	"testing"
)

type testBaseline struct {
	Files map[string]string `json:"files"`
	Count int               `json:"count"`
}

func TestNewStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "baselines")
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore() error: %v", err)
	}
	if store.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", store.Dir(), dir)
	}
}

func TestSaveAndLoad(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	original := testBaseline{
		Files: map[string]string{
			"/etc/passwd": "abc123",
			"/etc/shadow": "def456",
		},
		Count: 2,
	}

	if err := store.Save("file-integrity", original); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if !store.Exists("file-integrity") {
		t.Error("Exists() = false after Save")
	}

	var loaded testBaseline
	ok, err := store.Load("file-integrity", &loaded)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !ok {
		t.Fatal("Load() returned false for existing baseline")
	}

	if loaded.Count != 2 {
		t.Errorf("Count = %d, want 2", loaded.Count)
	}
	if loaded.Files["/etc/passwd"] != "abc123" {
		t.Errorf("Files[/etc/passwd] = %q", loaded.Files["/etc/passwd"])
	}
}

func TestLoadMissing(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var loaded testBaseline
	ok, err := store.Load("nonexistent", &loaded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected ok=false for missing baseline")
	}
}

func TestExists(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if store.Exists("nope") {
		t.Error("Exists() = true for missing baseline")
	}

	if err := store.Save("test", map[string]string{"a": "b"}); err != nil {
		t.Fatal(err)
	}
	if !store.Exists("test") {
		t.Error("Exists() = false after Save")
	}
}

func TestDelete(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Save("test", "data"); err != nil {
		t.Fatal(err)
	}
	if !store.Exists("test") {
		t.Fatal("baseline should exist after save")
	}

	if err := store.Delete("test"); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	if store.Exists("test") {
		t.Error("baseline should not exist after delete")
	}

	// Delete nonexistent should not error
	if err := store.Delete("test"); err != nil {
		t.Fatalf("Delete() nonexistent error: %v", err)
	}
}

func TestSaveOverwrite(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	_ = store.Save("test", testBaseline{Count: 1})
	_ = store.Save("test", testBaseline{Count: 2})

	var loaded testBaseline
	ok, _ := store.Load("test", &loaded)
	if !ok {
		t.Fatal("Load failed")
	}
	if loaded.Count != 2 {
		t.Errorf("Count = %d, want 2 after overwrite", loaded.Count)
	}
}

func TestConcurrentAccess(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(n int) {
			_ = store.Save("concurrent", testBaseline{Count: n})
			var b testBaseline
			_, _ = store.Load("concurrent", &b)
			done <- true
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
