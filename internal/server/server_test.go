package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jclement/tripline/pkg/finding"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{
		Addr:           ":0",
		DataDir:        t.TempDir(),
		Password:       "testpass",
		PublishSecrets: []string{"agent-secret-1", "agent-secret-2"},
		WebRoot:        "",
	})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewRequiresPassword(t *testing.T) {
	_, err := New(Config{
		DataDir:        t.TempDir(),
		PublishSecrets: []string{"x"},
	})
	if err == nil {
		t.Error("expected error for missing password")
	}
}

func TestNewRequiresSecrets(t *testing.T) {
	_, err := New(Config{
		DataDir:  t.TempDir(),
		Password: "x",
	})
	if err == nil {
		t.Error("expected error for missing publish secrets")
	}
}

func TestIngestFindings(t *testing.T) {
	s := testServer(t)

	findings := []finding.Finding{{
		Hostname:  "server1",
		Module:    "file-integrity",
		FindingID: "file-modified:/etc/passwd",
		Severity:  finding.SeverityHigh,
		Status:    finding.StatusNew,
		Summary:   "passwd modified",
	}}

	body, _ := json.Marshal(findings)
	req := httptest.NewRequest("POST", "/api/findings", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-secret-1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var result map[string]int
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["ingested"] != 1 {
		t.Errorf("ingested = %d, want 1", result["ingested"])
	}
}

func TestIngestRequiresSecret(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal([]finding.Finding{})
	req := httptest.NewRequest("POST", "/api/findings", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestIngestRejectsWrongSecret(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal([]finding.Finding{})
	req := httptest.NewRequest("POST", "/api/findings", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMultipleSecretsWork(t *testing.T) {
	s := testServer(t)

	for _, secret := range []string{"agent-secret-1", "agent-secret-2"} {
		findings := []finding.Finding{{
			Hostname: "host-" + secret, Module: "test", FindingID: "test-1",
			Severity: finding.SeverityInfo, Summary: "test",
		}}
		body, _ := json.Marshal(findings)
		req := httptest.NewRequest("POST", "/api/findings", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != 200 {
			t.Errorf("secret %s: status = %d", secret, w.Code)
		}
	}
}

func TestGetStats(t *testing.T) {
	s := testServer(t)

	findings := []finding.Finding{
		{Hostname: "h1", Module: "ssh", FindingID: "ssh-1", Severity: finding.SeverityCritical, Status: finding.StatusNew, Summary: "bad"},
		{Hostname: "h2", Module: "ports", FindingID: "port-1", Severity: finding.SeverityHigh, Status: finding.StatusNew, Summary: "new port"},
	}
	body, _ := json.Marshal(findings)
	req := httptest.NewRequest("POST", "/api/findings", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer agent-secret-1")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	req = httptest.NewRequest("GET", "/api/stats", nil)
	req.AddCookie(&http.Cookie{Name: "trapline_session", Value: "testpass"})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("stats status = %d", w.Code)
	}

	var stats map[string]int
	json.Unmarshal(w.Body.Bytes(), &stats)
	if stats["hosts"] != 2 {
		t.Errorf("hosts = %d, want 2", stats["hosts"])
	}
}

func TestDashboardRequiresPassword(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("password")) {
		t.Error("expected login page")
	}
}

func TestDashboardWithPassword(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "trapline_session", Value: "testpass"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("TRAPLINE")) {
		t.Error("expected dashboard content")
	}
}

func TestUpsertIncrementsHitCount(t *testing.T) {
	s := testServer(t)

	f := []finding.Finding{{
		Hostname: "h1", Module: "test", FindingID: "test-1",
		Severity: finding.SeverityHigh, Summary: "same finding",
	}}

	for i := 0; i < 3; i++ {
		body, _ := json.Marshal(f)
		req := httptest.NewRequest("POST", "/api/findings", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer agent-secret-1")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
	}

	req := httptest.NewRequest("GET", "/api/findings", nil)
	req.AddCookie(&http.Cookie{Name: "trapline_session", Value: "testpass"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	type Row struct {
		HitCount int `json:"hit_count"`
	}
	var results []Row
	json.Unmarshal(w.Body.Bytes(), &results)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].HitCount != 3 {
		t.Errorf("hit_count = %d, want 3", results[0].HitCount)
	}
}

func TestWebRootPrefix(t *testing.T) {
	s, err := New(Config{
		Addr:           ":0",
		DataDir:        t.TempDir(),
		Password:       "testpass",
		PublishSecrets: []string{"secret"},
		WebRoot:        "/trapline",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	req := httptest.NewRequest("GET", "/trapline/", nil)
	req.AddCookie(&http.Cookie{Name: "trapline_session", Value: "testpass"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("dashboard at /trapline/ = %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/trapline/api/stats", nil)
	req.AddCookie(&http.Cookie{Name: "trapline_session", Value: "testpass"})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("stats at /trapline/api/stats = %d", w.Code)
	}

	req = httptest.NewRequest("GET", "/trapline", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 301 {
		t.Errorf("redirect at /trapline = %d, want 301", w.Code)
	}
}

// Ensure unused import doesn't cause issues
var _ http.Handler
