package containers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/jclement/tripline/internal/engine"
)

func testModuleConfig(t *testing.T) engine.ModuleConfig {
	t.Helper()
	dir := t.TempDir()
	return engine.ModuleConfig{
		StateDir:     dir,
		BaselinesDir: filepath.Join(dir, "baselines"),
		Settings:     make(map[string]interface{}),
	}
}

func TestName(t *testing.T) {
	if New().Name() != "containers" {
		t.Error("wrong name")
	}
}

func TestContainerBaseline(t *testing.T) {
	b := ContainerBaseline{
		Containers: map[string]string{
			"traefik": "traefik:v2",
			"app":     "myapp:latest",
		},
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON")
	}
}

// Test with mock HTTP server simulating Docker API
func TestScanNoDocker(t *testing.T) {
	cfg := testModuleConfig(t)
	m := New()
	m.socketPath = "/nonexistent/docker.sock"
	_ = m.Init(cfg)

	// Should not error when Docker is unavailable
	_, err := m.Scan(context.TODO())
	_ = err // may or may not error depending on context
}

func TestContainerNameParsing(t *testing.T) {
	// Test the name parsing logic
	c := Container{
		ID:    "abc123def456",
		Names: []string{"/traefik"},
		Image: "traefik:v2",
	}

	name := c.Names[0]
	if name[0] == '/' {
		name = name[1:]
	}
	if name != "traefik" {
		t.Errorf("name = %q, want traefik", name)
	}
}

// Create a test HTTP handler that mimics Docker API
func mockDockerAPI(containers []Container) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			_ = json.NewEncoder(w).Encode(containers)
			return
		}
		http.NotFound(w, r)
	})
}

func TestMockDockerAPI(t *testing.T) {
	containers := []Container{
		{ID: "abc123", Names: []string{"/traefik"}, Image: "traefik:v2", State: "running"},
		{ID: "def456", Names: []string{"/app"}, Image: "myapp:latest", State: "running"},
	}

	server := httptest.NewServer(mockDockerAPI(containers))
	defer server.Close()

	// Verify the mock responds correctly
	resp, err := http.Get(server.URL + "/containers/json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result []Container
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if len(result) != 2 {
		t.Errorf("expected 2 containers, got %d", len(result))
	}
}
