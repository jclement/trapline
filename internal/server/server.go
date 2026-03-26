package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jclement/tripline/pkg/finding"
)

// Server is the trapline dashboard server.
type Server struct {
	db             *sql.DB
	password       string
	publishSecrets map[string]bool // set of valid agent secrets
	webRoot        string          // URL prefix for reverse proxy (e.g., "/trapline")
	addr           string
	mux            *http.ServeMux
}

// Config holds server configuration. All fields can be set via CLI flags or env vars.
type Config struct {
	Addr           string   // --addr / ADDR (default ":8080")
	DataDir        string   // --data / DATA_DIR
	Password       string   // --password / PASSWORD (required, for web UI)
	PublishSecrets []string // --publish-secrets / PUBLISH_SECRETS (comma-sep, for agents)
	WebRoot        string   // --web-root / WEB_ROOT (URL prefix, e.g., "/trapline")
}

// New creates a new server.
func New(cfg Config) (*Server, error) {
	if cfg.Password == "" {
		return nil, fmt.Errorf("password is required (--password or PASSWORD env)")
	}
	if len(cfg.PublishSecrets) == 0 {
		return nil, fmt.Errorf("at least one publish secret is required (--publish-secrets or PUBLISH_SECRETS env)")
	}

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, err
	}

	dbPath := filepath.Join(cfg.DataDir, "server.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := migrateServer(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	// Normalize web root
	webRoot := strings.TrimRight(cfg.WebRoot, "/")

	secrets := make(map[string]bool)
	for _, s := range cfg.PublishSecrets {
		s = strings.TrimSpace(s)
		if s != "" {
			secrets[s] = true
		}
	}

	s := &Server{
		db:             db,
		password:       cfg.Password,
		publishSecrets: secrets,
		webRoot:        webRoot,
		addr:           cfg.Addr,
		mux:            http.NewServeMux(),
	}

	// Register routes with web root prefix
	prefix := webRoot
	s.mux.HandleFunc(prefix+"/", s.handleDashboard)
	s.mux.HandleFunc(prefix+"/api/findings", s.handleFindings)
	s.mux.HandleFunc(prefix+"/api/hosts", s.handleHosts)
	s.mux.HandleFunc(prefix+"/api/stats", s.handleStats)

	// Redirect bare prefix to prefix/
	if prefix != "" {
		s.mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
		})
	}

	return s, nil
}

func migrateServer(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			hostname TEXT NOT NULL,
			module TEXT NOT NULL,
			finding_id TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'new',
			summary TEXT NOT NULL,
			detail TEXT,
			trapline_version TEXT,
			scan_id TEXT,
			received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			hit_count INTEGER NOT NULL DEFAULT 1,
			resolved_at DATETIME,
			UNIQUE(hostname, module, finding_id)
		);

		CREATE INDEX IF NOT EXISTS idx_findings_hostname ON findings(hostname);
		CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
		CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
		CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
	`)
	return err
}

// Handler returns the HTTP handler (for testing and reverse proxies).
func (s *Server) Handler() http.Handler {
	return s.mux
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      s.mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

// Close closes the database.
func (s *Server) Close() error {
	return s.db.Close()
}

// --- Auth ---

// requirePublishSecret checks that the request has a valid agent publish secret.
func (s *Server) requirePublishSecret(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized: missing Bearer token", http.StatusUnauthorized)
		return false
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if !s.publishSecrets[token] {
		http.Error(w, "unauthorized: invalid publish secret", http.StatusUnauthorized)
		return false
	}
	return true
}

// requirePassword checks the web UI password via cookie or query param.
func (s *Server) requirePassword(w http.ResponseWriter, r *http.Request) bool {
	// Check cookie first
	if c, err := r.Cookie("trapline_session"); err == nil && c.Value == s.password {
		return true
	}
	// Check query param (for initial login)
	if r.URL.Query().Get("password") == s.password {
		http.SetCookie(w, &http.Cookie{
			Name:     "trapline_session",
			Value:    s.password,
			Path:     s.webRoot + "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400 * 30,
		})
		return true
	}
	// Check form POST
	if r.Method == http.MethodPost {
		if r.FormValue("password") == s.password {
			http.SetCookie(w, &http.Cookie{
				Name:     "trapline_session",
				Value:    s.password,
				Path:     s.webRoot + "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400 * 30,
			})
			return true
		}
	}
	return false
}

// --- API Handlers ---

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.ingestFindings(w, r)
	case http.MethodGet:
		s.listFindings(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) ingestFindings(w http.ResponseWriter, r *http.Request) {
	if !s.requirePublishSecret(w, r) {
		return
	}

	var findings []finding.Finding
	if err := json.NewDecoder(r.Body).Decode(&findings); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	ingested := 0
	for _, f := range findings {
		detail, _ := json.Marshal(f.Detail)
		_, err := s.db.Exec(`
			INSERT INTO findings (hostname, module, finding_id, severity, status, summary, detail, trapline_version, scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(hostname, module, finding_id) DO UPDATE SET
				severity = excluded.severity,
				summary = excluded.summary,
				detail = excluded.detail,
				trapline_version = excluded.trapline_version,
				scan_id = excluded.scan_id,
				last_seen = CURRENT_TIMESTAMP,
				hit_count = hit_count + 1,
				status = 'active'
		`, f.Hostname, f.Module, f.FindingID, string(f.Severity), string(f.Status), f.Summary, string(detail), f.TraplineVersion, f.ScanID)
		if err == nil {
			ingested++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"ingested": ingested})
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	// GET requires either publish secret or web password
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		if !s.requirePublishSecret(w, r) {
			return
		}
	} else if !s.requirePassword(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	hostname := r.URL.Query().Get("host")
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}

	query := "SELECT hostname, module, finding_id, severity, status, summary, detail, last_seen, hit_count FROM findings WHERE status = ?"
	args := []interface{}{status}

	if hostname != "" {
		query += " AND hostname = ?"
		args = append(args, hostname)
	}
	if severity != "" {
		query += " AND severity = ?"
		args = append(args, severity)
	}
	query += " ORDER BY last_seen DESC LIMIT 500"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type FindingRow struct {
		Hostname  string `json:"hostname"`
		Module    string `json:"module"`
		FindingID string `json:"finding_id"`
		Severity  string `json:"severity"`
		Status    string `json:"status"`
		Summary   string `json:"summary"`
		Detail    string `json:"detail"`
		LastSeen  string `json:"last_seen"`
		HitCount  int    `json:"hit_count"`
	}

	var results []FindingRow
	for rows.Next() {
		var f FindingRow
		rows.Scan(&f.Hostname, &f.Module, &f.FindingID, &f.Severity, &f.Status, &f.Summary, &f.Detail, &f.LastSeen, &f.HitCount)
		results = append(results, f)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if !s.requirePassword(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := s.db.Query(`
		SELECT hostname,
			COUNT(*) as total_findings,
			SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
			SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
			MAX(last_seen) as last_report
		FROM findings WHERE status IN ('active', 'new')
		GROUP BY hostname
		ORDER BY critical DESC, high DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type HostRow struct {
		Hostname   string `json:"hostname"`
		Total      int    `json:"total_findings"`
		Critical   int    `json:"critical"`
		High       int    `json:"high"`
		LastReport string `json:"last_report"`
	}

	var results []HostRow
	for rows.Next() {
		var h HostRow
		rows.Scan(&h.Hostname, &h.Total, &h.Critical, &h.High, &h.LastReport)
		results = append(results, h)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.requirePassword(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var totalHosts, totalFindings, critical, high int
	s.db.QueryRow("SELECT COUNT(DISTINCT hostname) FROM findings WHERE status IN ('active','new')").Scan(&totalHosts)
	s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE status IN ('active','new')").Scan(&totalFindings)
	s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE status IN ('active','new') AND severity = 'critical'").Scan(&critical)
	s.db.QueryRow("SELECT COUNT(*) FROM findings WHERE status IN ('active','new') AND severity = 'high'").Scan(&high)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{
		"hosts":    totalHosts,
		"findings": totalFindings,
		"critical": critical,
		"high":     high,
	})
}

// --- Dashboard ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Strip web root prefix for path matching
	path := strings.TrimPrefix(r.URL.Path, s.webRoot)
	if path != "/" && path != "" {
		http.NotFound(w, r)
		return
	}

	if !s.requirePassword(w, r) {
		w.Header().Set("Content-Type", "text/html")
		loginTmpl.Execute(w, map[string]string{"WebRoot": s.webRoot})
		return
	}

	w.Header().Set("Content-Type", "text/html")
	dashboardTmpl.Execute(w, map[string]string{
		"WebRoot":  s.webRoot,
		"Password": s.password,
	})
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html><head>
<title>Trapline</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0a; color: #e0e0e0; font-family: 'SF Mono', 'Fira Code', monospace; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
  .login { background: #1a1a1a; padding: 2rem; border-radius: 8px; border: 1px solid #333; width: 400px; }
  h1 { color: #00cccc; margin-bottom: 0.5rem; }
  p { color: #666; margin-bottom: 1.5rem; font-size: 0.9rem; }
  input { width: 100%; padding: 0.75rem; background: #0a0a0a; border: 1px solid #333; color: #e0e0e0; border-radius: 4px; font-family: inherit; font-size: 1rem; margin-bottom: 1rem; }
  button { width: 100%; padding: 0.75rem; background: #00cccc; color: #0a0a0a; border: none; border-radius: 4px; font-family: inherit; font-size: 1rem; cursor: pointer; font-weight: bold; }
  button:hover { background: #00aaaa; }
</style>
</head><body>
<div class="login">
  <h1>TRAPLINE</h1>
  <p>Enter your dashboard password.</p>
  <form method="POST" action="{{.WebRoot}}/">
    <input type="password" name="password" placeholder="Password" autofocus>
    <button type="submit">Login</button>
  </form>
</div>
</body></html>`))

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html><head>
<title>Trapline Dashboard</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0a0a; color: #e0e0e0; font-family: 'SF Mono', 'Fira Code', monospace; padding: 1rem; }
  .header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 0; border-bottom: 1px solid #222; margin-bottom: 1rem; }
  .header h1 { color: #00cccc; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1a1a1a; padding: 1rem; border-radius: 8px; border: 1px solid #222; text-align: center; }
  .stat .num { font-size: 2rem; font-weight: bold; }
  .stat .label { color: #666; font-size: 0.8rem; }
  .stat.critical .num { color: #ff0000; }
  .stat.high .num { color: #cc4400; }
  .stat.hosts .num { color: #00cccc; }
  .stat.findings .num { color: #ffaa00; }
  h2 { color: #888; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 0.5rem; }
  .host-list { margin-bottom: 2rem; }
  .host { background: #1a1a1a; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 3px solid #333; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .host:hover { border-left-color: #00cccc; background: #222; }
  .host.has-critical { border-left-color: #ff0000; }
  .host.has-high { border-left-color: #cc4400; }
  .host-name { font-weight: bold; }
  .host-badges span { padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.75rem; margin-left: 0.25rem; }
  .badge-critical { background: #ff0000; color: white; }
  .badge-high { background: #cc4400; color: white; }
  .badge-total { background: #333; color: #aaa; }
  .finding-list { margin-bottom: 2rem; }
  .finding { background: #1a1a1a; padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 0.5rem; border-left: 3px solid #333; }
  .finding.critical { border-left-color: #ff0000; }
  .finding.high { border-left-color: #cc4400; }
  .finding.medium { border-left-color: #aa8800; }
  .finding .sev { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.7rem; font-weight: bold; margin-right: 0.5rem; }
  .finding .sev.critical { background: #ff0000; color: white; }
  .finding .sev.high { background: #cc4400; color: white; }
  .finding .sev.medium { background: #aa8800; color: white; }
  .finding .sev.info { background: #444; color: #aaa; }
  .finding .summary { font-weight: bold; }
  .finding .meta { color: #666; font-size: 0.8rem; margin-top: 0.25rem; }
  .refresh { color: #666; font-size: 0.8rem; }
  .empty { color: #444; text-align: center; padding: 2rem; }
  select { background: #1a1a1a; color: #e0e0e0; border: 1px solid #333; padding: 0.5rem; border-radius: 4px; font-family: inherit; margin-bottom: 1rem; }
</style>
</head><body>
<div class="header">
  <h1>TRAPLINE</h1>
  <span class="refresh">Auto-refreshes every 30s</span>
</div>

<div class="stats" id="stats"></div>

<h2>Hosts</h2>
<div class="host-list" id="hosts"></div>

<div>
  <select id="host-select" onchange="filterHost()">
    <option value="">All hosts</option>
  </select>
</div>

<h2>Active Findings</h2>
<div class="finding-list" id="findings"></div>

<script>
const BASE = '{{.WebRoot}}';
const PASSWORD = '{{.Password}}';

async function api(path) {
  const res = await fetch(BASE + path + (path.includes('?') ? '&' : '?') + 'password=' + encodeURIComponent(PASSWORD));
  return res.json();
}

async function load() {
  try {
    const [stats, hosts, findings] = await Promise.all([
      api('/api/stats'), api('/api/hosts'), api('/api/findings')
    ]);
    renderStats(stats);
    renderHosts(hosts || []);
    renderFindings(findings || []);
  } catch(e) { console.error('Failed to load:', e); }
}

function renderStats(s) {
  document.getElementById('stats').innerHTML =
    '<div class="stat hosts"><div class="num">' + s.hosts + '</div><div class="label">Hosts</div></div>' +
    '<div class="stat findings"><div class="num">' + s.findings + '</div><div class="label">Findings</div></div>' +
    '<div class="stat critical"><div class="num">' + s.critical + '</div><div class="label">Critical</div></div>' +
    '<div class="stat high"><div class="num">' + s.high + '</div><div class="label">High</div></div>';
}

function renderHosts(hosts) {
  if (!hosts.length) { document.getElementById('hosts').innerHTML = '<div class="empty">No hosts reporting yet.</div>'; return; }
  let html = '', select = '<option value="">All hosts</option>';
  hosts.forEach(h => {
    let cls = h.critical > 0 ? 'has-critical' : h.high > 0 ? 'has-high' : '';
    let badges = '<span class="badge-total">' + h.total_findings + '</span>';
    if (h.critical > 0) badges = '<span class="badge-critical">' + h.critical + ' crit</span>' + badges;
    if (h.high > 0) badges = '<span class="badge-high">' + h.high + ' high</span>' + badges;
    html += '<div class="host ' + cls + '" onclick="selectHost(\'' + h.hostname + '\')"><span class="host-name">' + h.hostname + '</span><span class="host-badges">' + badges + '</span></div>';
    select += '<option value="' + h.hostname + '">' + h.hostname + '</option>';
  });
  document.getElementById('hosts').innerHTML = html;
  document.getElementById('host-select').innerHTML = select;
}

function renderFindings(findings) {
  if (!findings.length) { document.getElementById('findings').innerHTML = '<div class="empty">All clear. No active findings.</div>'; return; }
  let html = '';
  findings.forEach(f => {
    html += '<div class="finding ' + f.severity + '"><span class="sev ' + f.severity + '">' + f.severity.toUpperCase() + '</span><span class="summary">' + esc(f.summary) + '</span><div class="meta">' + f.hostname + ' / ' + f.module + ' / ' + f.finding_id + ' / seen ' + f.hit_count + 'x / last ' + f.last_seen + '</div></div>';
  });
  document.getElementById('findings').innerHTML = html;
}

function selectHost(h) { document.getElementById('host-select').value = h; filterHost(); }

async function filterHost() {
  const host = document.getElementById('host-select').value;
  const findings = await api('/api/findings' + (host ? '?host=' + encodeURIComponent(host) : ''));
  renderFindings(findings || []);
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

load();
setInterval(load, 30000);
</script>
</body></html>`))
