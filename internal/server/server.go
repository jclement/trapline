// Package server implements the Trapline built-in dashboard server, which provides
// both a web-based UI for human operators and a JSON API for remote trapline agents.
//
// # Architecture
//
// The server is a single self-contained HTTP server that embeds everything it needs:
// a SQLite database for persistence, Go HTML templates for the web dashboard, and a
// small REST API for agent-to-server communication. There are no external dependencies
// beyond the SQLite driver (modernc.org/sqlite, pure-Go, CGO_ENABLED=0 compatible).
//
// The dashboard renders a dark-themed, auto-refreshing single-page view of all
// security findings reported by trapline agents across the fleet. It uses vanilla
// JavaScript (no frameworks) with a 30-second polling interval and supports host-level
// filtering via a dropdown. The CSS uses a monospace font stack (SF Mono / Fira Code)
// and a #0a0a0a background with #00cccc accent colors.
//
// # Dual Authentication Model
//
// The server enforces two separate authentication mechanisms:
//
//   - Publish secrets (for agents): One or more shared secrets passed via the
//     Authorization: Bearer <token> header. Agents use these to POST findings to
//     /api/findings. Multiple secrets are supported to allow rotation without downtime.
//     Configured via --publish-secrets flag or PUBLISH_SECRETS env (comma-separated).
//
//   - Dashboard password (for the web UI): A single password used to access the
//     browser dashboard and the GET endpoints. Authentication is checked in three ways,
//     in priority order: (1) trapline_session cookie, (2) X-Trapline-Password header,
//     (3) POST form field "password". On successful auth, a 30-day HttpOnly cookie is
//     set with SameSite=Strict. Configured via --password flag or PASSWORD env.
//
// The GET /api/findings endpoint accepts either authentication method (Bearer token
// or dashboard password), so both agents and browser sessions can read findings.
//
// # Web Root / Reverse Proxy Support
//
// The --web-root / WEB_ROOT option allows mounting the dashboard under a URL prefix
// (e.g., "/trapline") for reverse proxy deployments. When set, all routes are
// registered under that prefix and the cookie path is scoped accordingly. A bare
// request to the prefix (without trailing slash) is 301-redirected to prefix/.
//
// Example Traefik configuration (Docker labels):
//
//	traefik.http.routers.trapline.rule=Host(`monitor.example.com`) && PathPrefix(`/trapline`)
//	traefik.http.services.trapline.loadbalancer.server.port=8080
//
// Example nginx location block:
//
//	location /trapline/ {
//	    proxy_pass http://127.0.0.1:8080/trapline/;
//	    proxy_set_header Host $host;
//	}
//
// # SQLite Schema
//
// The server stores all findings in a single "findings" table with the following schema:
//
//	findings (
//	    id               INTEGER PRIMARY KEY AUTOINCREMENT,
//	    hostname         TEXT NOT NULL,          -- agent hostname
//	    module           TEXT NOT NULL,          -- scanner module name (e.g., "ports", "certs")
//	    finding_id       TEXT NOT NULL,          -- stable identifier for deduplication
//	    severity         TEXT NOT NULL,          -- "critical", "high", "medium", "info"
//	    status           TEXT NOT NULL DEFAULT 'new',  -- "new", "active", "resolved"
//	    summary          TEXT NOT NULL,          -- one-line human description
//	    detail           TEXT,                   -- JSON-encoded map[string]interface{} from finding.Detail
//	    trapline_version TEXT,                   -- version of the agent that reported this
//	    scan_id          TEXT,                   -- unique scan run identifier
//	    received_at      DATETIME DEFAULT CURRENT_TIMESTAMP, -- when the server first received it
//	    first_seen       DATETIME DEFAULT CURRENT_TIMESTAMP, -- when this finding first appeared
//	    last_seen        DATETIME DEFAULT CURRENT_TIMESTAMP, -- updated on each re-report
//	    hit_count        INTEGER DEFAULT 1,      -- incremented on each re-report
//	    resolved_at      DATETIME,               -- set when status transitions to "resolved"
//	    UNIQUE(hostname, module, finding_id)      -- upsert key for deduplication
//	)
//
// WAL journal mode is enabled for concurrent read performance. Three indexes cover
// the most common query patterns: by hostname, severity, and status. An additional
// index on last_seen supports the default ORDER BY in the findings list.
//
// # API Endpoints
//
//	POST /api/findings   -- Ingest findings from agents (requires Bearer token).
//	                        Accepts a JSON array of finding.Finding structs.
//	                        Uses INSERT ... ON CONFLICT to upsert: new findings are
//	                        inserted with status "new"; existing findings (same
//	                        hostname+module+finding_id) have their severity, summary,
//	                        detail, and version updated, last_seen is bumped, hit_count
//	                        is incremented, and status is set to "active".
//	                        Returns {"ingested": N} with the count of successfully stored rows.
//
//	GET  /api/findings   -- List findings (requires Bearer token OR dashboard password).
//	                        Query params: host (filter by hostname), severity (filter by
//	                        severity level), status (default "active"). Returns up to 500
//	                        findings ordered by last_seen DESC as a JSON array.
//
//	GET  /api/hosts      -- List hosts with finding counts (requires dashboard password).
//	                        Returns hostname, total active findings, critical count, high
//	                        count, and last report timestamp. Ordered by critical DESC,
//	                        then high DESC.
//
//	GET  /api/stats      -- Aggregate statistics (requires dashboard password).
//	                        Returns {"hosts": N, "findings": N, "critical": N, "high": N}
//	                        counting only active/new findings.
//
// # Embedded Web Dashboard
//
// The dashboard is rendered from two Go html/template variables:
//
//   - loginTmpl: A minimal centered login form. Dark background, single password input,
//     POSTs to the web root. No JavaScript required for login.
//
//   - dashboardTmpl: The main dashboard page. Renders stat cards (hosts, findings,
//     critical, high) in a responsive CSS grid, a host list with severity badges and
//     click-to-filter, a host dropdown for filtering, and a findings list sorted by
//     recency. All data is fetched client-side via the JSON API using the dashboard
//     password as a query parameter. Auto-refreshes every 30 seconds via setInterval.
//     HTML is escaped client-side via a DOM-based esc() function to prevent XSS.
//
// The CSS uses severity-keyed color coding throughout: #ff0000 for critical,
// #cc4400 for high, #aa8800 for medium, #444/#aaa for info. Host cards get colored
// left borders based on their worst severity. The layout is fully responsive via
// CSS grid auto-fit.
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
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/jclement/tripline/pkg/finding"
)

// Server is the trapline dashboard server. It holds the database handle, authentication
// credentials, routing configuration, and the HTTP mux. A single Server instance serves
// both the agent API (Bearer-token authenticated) and the web dashboard (password
// authenticated). The zero value is not usable; always construct via [New].
type Server struct {
	db             *sql.DB                // SQLite database connection (WAL mode, pure-Go driver)
	password       string                 // dashboard password for web UI authentication
	publishSecrets map[string]bool        // set of valid agent Bearer tokens; checked via map lookup for O(1) validation
	webRoot        string                 // URL prefix for reverse proxy mounting (e.g., "/trapline"), empty string for root
	addr           string                 // listen address in host:port format (e.g., ":8080")
	mux            *http.ServeMux         // HTTP request multiplexer with all routes registered at construction time
	authAttempts   map[string][]time.Time // tracks failed auth attempts by IP for rate limiting
	authAttemptsMu sync.Mutex             // protects authAttempts
}

// Config holds server configuration. All fields can be set via CLI flags or environment
// variables. Password and at least one PublishSecret are required; the constructor
// validates this and returns an error if they are missing.
type Config struct {
	Addr           string   // --addr / ADDR: TCP listen address (default ":8080")
	DataDir        string   // --data / DATA_DIR: directory for server.db SQLite file (created if needed)
	Password       string   // --password / PASSWORD: required dashboard login password for the web UI
	PublishSecrets []string // --publish-secrets / PUBLISH_SECRETS: one or more Bearer tokens for agent auth (comma-separated in env)
	WebRoot        string   // --web-root / WEB_ROOT: URL prefix for reverse proxy deployment (e.g., "/trapline")
}

// New creates and initializes a new Server from the given configuration. It validates
// that required fields (Password, PublishSecrets) are present, creates the data
// directory if needed, opens the SQLite database with WAL journaling, runs schema
// migrations, normalizes the web root, and registers all HTTP routes. The caller
// must call [Server.Close] when done to release the database handle.
func New(cfg Config) (*Server, error) {
	// Validate required configuration. Both auth mechanisms must be configured:
	// the password for dashboard users and at least one publish secret for agents.
	if cfg.Password == "" {
		return nil, fmt.Errorf("password is required (--password or PASSWORD env)")
	}
	if len(cfg.PublishSecrets) == 0 {
		return nil, fmt.Errorf("at least one publish secret is required (--publish-secrets or PUBLISH_SECRETS env)")
	}

	// Ensure the data directory exists with restrictive permissions (0700)
	// since it will contain the SQLite database with security findings.
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, err
	}

	// Open the SQLite database with WAL (Write-Ahead Logging) journal mode for
	// better concurrent read performance. The pure-Go modernc.org/sqlite driver
	// is used so the binary can be built with CGO_ENABLED=0.
	dbPath := filepath.Join(cfg.DataDir, "server.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Run idempotent schema migrations (CREATE TABLE IF NOT EXISTS / CREATE INDEX
	// IF NOT EXISTS). On failure, close the database to avoid leaking the handle.
	if err := migrateServer(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	// Normalize web root by stripping any trailing slash so that route
	// registration produces clean paths like "/trapline/" not "/trapline//".
	// An empty string means the server is mounted at the domain root.
	webRoot := strings.TrimRight(cfg.WebRoot, "/")

	// Build the publish secrets set. Whitespace is trimmed and empty strings
	// are skipped to tolerate trailing commas in the PUBLISH_SECRETS env var.
	// Using a map[string]bool gives O(1) token validation in requirePublishSecret.
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
		authAttempts:   make(map[string][]time.Time),
	}

	// Register routes under the web root prefix. The trailing-slash pattern
	// on handleDashboard acts as a catch-all for the prefix subtree. The API
	// routes are registered as exact paths (no trailing slash).
	prefix := webRoot
	s.mux.HandleFunc(prefix+"/", s.handleDashboard)            // GET/POST: dashboard HTML + login flow
	s.mux.HandleFunc(prefix+"/api/findings", s.handleFindings) // GET: list findings; POST: ingest from agents
	s.mux.HandleFunc(prefix+"/api/hosts", s.handleHosts)       // GET: host summary with severity counts
	s.mux.HandleFunc(prefix+"/api/stats", s.handleStats)       // GET: aggregate statistics for dashboard cards

	// When a web root is configured, redirect requests to the bare prefix
	// (e.g., "/trapline") to the canonical form with trailing slash ("/trapline/").
	// This prevents 404s when users type the URL without a trailing slash.
	if prefix != "" {
		s.mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, prefix+"/", http.StatusMovedPermanently)
		})
	}

	return s, nil
}

// migrateServer runs idempotent DDL to ensure the findings table and its indexes
// exist. All statements use IF NOT EXISTS so this is safe to call on every startup.
// The schema uses a UNIQUE constraint on (hostname, module, finding_id) which serves
// as the upsert key in ingestFindings -- if the same finding is reported again, the
// existing row is updated rather than duplicated. Four indexes are created to support
// the most common query patterns in the dashboard and API:
//   - idx_findings_hostname: fast filtering by host in listFindings and handleHosts
//   - idx_findings_severity: fast filtering by severity level
//   - idx_findings_status: fast filtering for active/new findings (used by almost every query)
//   - idx_findings_last_seen: fast ORDER BY last_seen DESC in the findings list
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

// Handler returns the underlying http.Handler for use in tests or when embedding
// the server behind another HTTP server or reverse proxy middleware. The returned
// handler has all routes pre-registered and is safe for concurrent use.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// ListenAndServe starts the HTTP server on the configured address. It sets
// conservative timeouts: 10s read (protects against slow clients), 30s write
// (allows time for database queries), and 120s idle (keeps connections open
// for the dashboard's 30-second polling interval without excessive churn).
// This method blocks until the server is shut down or encounters a fatal error.
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

// Close releases the SQLite database handle. It should be called when the server
// is shutting down, typically via a defer in the caller. Any in-flight requests
// that are still using the database may fail after this call.
func (s *Server) Close() error {
	return s.db.Close()
}

// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------
// Trapline uses two independent auth mechanisms. Agent endpoints require a
// Bearer token (publish secret). Dashboard/web endpoints require the dashboard
// password. Both functions return true if auth succeeded, or write an HTTP
// error and return false if it failed. Callers should return immediately on
// false since the response has already been written.
// ---------------------------------------------------------------------------

// checkRateLimit returns false (and writes a 429 response) if the given IP
// has exceeded 5 failed authentication attempts in the last minute. This
// provides basic brute-force protection for both dashboard and agent auth.
func (s *Server) checkRateLimit(w http.ResponseWriter, ip string) bool {
	s.authAttemptsMu.Lock()
	defer s.authAttemptsMu.Unlock()

	cutoff := time.Now().Add(-1 * time.Minute)
	attempts := s.authAttempts[ip]

	// Prune expired entries.
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	s.authAttempts[ip] = valid

	if len(valid) >= 5 {
		http.Error(w, "too many failed auth attempts, try again later", http.StatusTooManyRequests)
		return false
	}
	return true
}

// recordFailedAuth records a failed authentication attempt for the given IP.
func (s *Server) recordFailedAuth(ip string) {
	s.authAttemptsMu.Lock()
	defer s.authAttemptsMu.Unlock()
	s.authAttempts[ip] = append(s.authAttempts[ip], time.Now())
}

// requirePublishSecret validates the agent's Bearer token against the set of
// configured publish secrets. This is the auth gate for POST /api/findings
// and optionally for GET /api/findings (agents can read back their own data).
//
// The token is extracted from the standard Authorization header in the format
// "Bearer <token>". The lookup is a simple map check (O(1)). No timing-safe
// comparison is used here because the map lookup on the raw string is already
// not constant-time; for production hardening, consider using a HMAC comparison.
//
// Returns true if the token is valid; returns false and writes a 401 response
// if the header is missing, malformed, or contains an unknown token.
func (s *Server) requirePublishSecret(w http.ResponseWriter, r *http.Request) bool {
	ip := r.RemoteAddr
	if !s.checkRateLimit(w, ip) {
		return false
	}

	// Extract the Authorization header value. Agents must send:
	//   Authorization: Bearer <publish-secret>
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		s.recordFailedAuth(ip)
		http.Error(w, "unauthorized: missing Bearer token", http.StatusUnauthorized)
		return false
	}
	// Strip the "Bearer " prefix to isolate the raw token, then check it
	// against the pre-built set. Missing keys return false from the map.
	token := strings.TrimPrefix(auth, "Bearer ")
	if !s.publishSecrets[token] {
		s.recordFailedAuth(ip)
		http.Error(w, "unauthorized: invalid publish secret", http.StatusUnauthorized)
		return false
	}
	return true
}

// requirePassword validates the dashboard password for web UI access. It checks
// three sources in priority order, returning true on the first match:
//
//  1. Cookie ("trapline_session"): Set after a successful login. Checked first
//     so that already-authenticated users do not need to re-submit credentials
//     on every request. The cookie value is the raw password (simple scheme;
//     appropriate for single-user dashboards over HTTPS).
//
//  2. X-Trapline-Password header: For programmatic API access from scripts that
//     cannot use cookies. Checked before POST form to allow header-based auth
//     on any HTTP method.
//
//  3. POST form field ("password"): Used by the HTML login form. When the user
//     submits the login form, the password is sent as a standard form field.
//     On match, a session cookie is set for future requests.
//
// The query parameter auth path has been removed to avoid leaking the password
// in server logs, browser history, and referrer headers.
//
// The session cookie is configured with:
//   - Path scoped to webRoot+"/" so it works correctly under reverse proxies
//   - HttpOnly=true to prevent JavaScript access (XSS mitigation)
//   - SameSite=Strict to prevent CSRF via cross-origin requests
//   - MaxAge=30 days (86400*30 seconds) for long-lived sessions
//
// Returns true if any source matched; returns false (without writing a response)
// if none matched. Unlike requirePublishSecret, this does NOT write a 401 --
// the caller is responsible for deciding what to do (e.g., show the login page).
func (s *Server) requirePassword(w http.ResponseWriter, r *http.Request) bool {
	ip := r.RemoteAddr
	if !s.checkRateLimit(w, ip) {
		return false
	}

	// Priority 1: Check the session cookie. If the user previously logged in
	// successfully, they will have this cookie set with the password value.
	if c, err := r.Cookie("trapline_session"); err == nil && c.Value == s.password {
		return true
	}
	// Priority 2: Check the X-Trapline-Password header. This supports
	// programmatic API access from scripts that cannot use cookies.
	if r.Header.Get("X-Trapline-Password") == s.password && r.Header.Get("X-Trapline-Password") != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "trapline_session",
			Value:    s.password,
			Path:     s.webRoot + "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   86400 * 30, // 30 days
		})
		return true
	}
	// Priority 3: Check the POST form body. This is used by the HTML login form.
	// Only checked on POST requests to avoid accidentally parsing GET request bodies.
	if r.Method == http.MethodPost {
		if r.FormValue("password") == s.password {
			http.SetCookie(w, &http.Cookie{
				Name:     "trapline_session",
				Value:    s.password,
				Path:     s.webRoot + "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   86400 * 30, // 30 days
			})
			return true
		}
	}
	s.recordFailedAuth(ip)
	return false
}

// ---------------------------------------------------------------------------
// API Handlers
// ---------------------------------------------------------------------------

// handleFindings is the route handler for /api/findings. It dispatches to
// ingestFindings for POST (agent publishes) and listFindings for GET (dashboard
// or agent reads). All other HTTP methods receive a 405 Method Not Allowed.
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

// ingestFindings handles POST /api/findings. This is the primary endpoint used by
// remote trapline agents to publish their scan results to the server.
//
// Authentication: Requires a valid Bearer token (publish secret).
//
// Request body: JSON array of finding.Finding structs. The Detail field (a free-form
// map[string]interface{}) is serialized to a JSON string for storage in the TEXT
// column, since SQLite does not have a native JSON column type.
//
// Upsert logic: Each finding is inserted using INSERT ... ON CONFLICT. The conflict
// key is (hostname, module, finding_id) -- the UNIQUE constraint in the schema. On
// conflict (i.e., the finding was previously reported), the following updates occur:
//   - severity, summary, detail, trapline_version, scan_id: overwritten with latest values
//   - last_seen: bumped to CURRENT_TIMESTAMP
//   - hit_count: incremented by 1 (tracks how many times this finding has been reported)
//   - status: set to "active" (re-activates findings that may have been manually resolved)
//
// Note: first_seen and received_at are NOT updated on conflict, preserving the
// original discovery timestamp.
//
// Errors during individual row inserts are silently skipped (the ingested count
// simply is not incremented). This is a deliberate design choice: a single malformed
// finding should not cause the entire batch to fail.
//
// Response: {"ingested": N} where N is the number of successfully stored findings.
func (s *Server) ingestFindings(w http.ResponseWriter, r *http.Request) {
	if !s.requirePublishSecret(w, r) {
		return
	}

	// Decode the request body as a JSON array of findings.
	var findings []finding.Finding
	if err := json.NewDecoder(r.Body).Decode(&findings); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	ingested := 0
	for _, f := range findings {
		// Serialize the Detail map to a JSON string for storage in the TEXT column.
		// Errors from json.Marshal on a map[string]interface{} are effectively impossible
		// since the data was just decoded from JSON, so the error is safely ignored.
		detail, _ := json.Marshal(f.Detail)

		// Upsert: insert new findings or update existing ones based on the
		// (hostname, module, finding_id) unique constraint. The ON CONFLICT clause
		// uses the "excluded" pseudo-table to reference the values that would have
		// been inserted, while "hit_count" (without prefix) references the existing row.
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

	// Return the count of successfully ingested findings as JSON.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"ingested": ingested})
}

// listFindings handles GET /api/findings. It returns a JSON array of findings
// filtered by optional query parameters. This endpoint is used both by the
// dashboard JavaScript (authenticated via password) and by agents that want to
// read back findings (authenticated via Bearer token).
//
// Authentication: Accepts either Bearer token OR dashboard password. The check
// examines the Authorization header first -- if it starts with "Bearer ", the
// publish secret path is used; otherwise, the password path is tried. This dual
// auth allows both agents and browser sessions to access the same data.
//
// Query parameters:
//   - host:     filter by exact hostname match (optional)
//   - severity: filter by exact severity level (optional)
//   - status:   filter by status (default: "active")
//
// The query is built dynamically by appending AND clauses for each provided filter.
// Results are ordered by last_seen DESC and limited to 500 rows to prevent
// unbounded responses from overwhelming the dashboard.
//
// Response: JSON array of FindingRow objects (or null if no results).
func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	// Dual auth: check for Bearer token first (agent path), fall back to
	// password auth (dashboard path). This ordering prevents the password
	// check from consuming a Bearer-authenticated request's cookie slot.
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		if !s.requirePublishSecret(w, r) {
			return
		}
	} else if !s.requirePassword(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract optional filter parameters from the query string.
	hostname := r.URL.Query().Get("host")
	severity := r.URL.Query().Get("severity")
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active" // Default to showing only active findings in the dashboard.
	}

	// Build the query dynamically. The base WHERE clause always filters by status.
	// Additional AND clauses are appended for each provided filter parameter.
	// Parameters are passed as positional args to prevent SQL injection.
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
	// Order by most recently seen first, with a hard limit of 500 to keep
	// response sizes manageable for the dashboard's auto-refresh cycle.
	query += " ORDER BY last_seen DESC LIMIT 500"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// FindingRow is the API response shape for a single finding. It mirrors the
	// database columns selected above. Detail is returned as a raw JSON string
	// (as stored in SQLite) rather than being re-parsed into a map.
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

// handleHosts handles GET /api/hosts. It returns a JSON array of host summaries,
// each containing the hostname, total active finding count, critical count, high
// count, and the timestamp of the most recent finding report.
//
// Authentication: Requires dashboard password only (not available to agents via
// Bearer token, since this is a dashboard-specific aggregation view).
//
// The query uses conditional SUM (CASE WHEN) to compute per-severity counts in a
// single pass over the findings table. Only active and new findings are included.
// Results are ordered by critical count descending, then high count descending,
// so the most problematic hosts appear at the top of the dashboard.
//
// Response: JSON array of HostRow objects (or null if no hosts are reporting).
func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	if !s.requirePassword(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Aggregate findings by hostname. The CASE WHEN expressions compute per-severity
	// counts without requiring separate queries. MAX(last_seen) gives the most recent
	// report time for each host, which is displayed in the dashboard host list.
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

	// HostRow is the API response shape for a single host summary.
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

// handleStats handles GET /api/stats. It returns aggregate statistics for the
// dashboard header cards: total distinct hosts, total findings, critical count,
// and high count. Only active and new findings are counted (resolved findings
// are excluded from the dashboard view).
//
// Authentication: Requires dashboard password only.
//
// The four counts are fetched via separate QueryRow calls rather than a single
// query with multiple aggregates. This is simple and clear; the performance cost
// is negligible since SQLite processes all four queries against the same cached
// pages and the idx_findings_status index covers the WHERE clause.
//
// Response: {"hosts": N, "findings": N, "critical": N, "high": N}
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.requirePassword(w, r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Four separate scalar queries for dashboard stat cards.
	// Each filters to active/new status to match what the dashboard displays.
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

// ---------------------------------------------------------------------------
// Dashboard (HTML UI)
// ---------------------------------------------------------------------------

// handleDashboard serves the main web dashboard at the root path (or web root
// prefix). It implements the complete login-to-dashboard flow:
//
//  1. Path validation: The handler is registered with a trailing-slash pattern
//     (e.g., "/trapline/"), which makes it a catch-all for the subtree. To avoid
//     serving the dashboard for API paths or unknown paths, it strips the web root
//     prefix and only proceeds if the remaining path is exactly "/" or "". All
//     other paths get a 404. (The API handlers are registered as exact-match
//     patterns and take precedence over this catch-all.)
//
//  2. Authentication check: If requirePassword returns false (no valid cookie,
//     query param, or POST form), the login template is rendered. The login page
//     contains a simple HTML form that POSTs the password back to this same
//     endpoint, where requirePassword will validate it and set the session cookie.
//
//  3. Dashboard rendering: On successful auth via POST, a 303 redirect to GET
//     is issued (POST-Redirect-GET pattern). On GET with a valid cookie, the
//     dashboard template is rendered with the web root. Client-side JavaScript
//     API calls rely on the session cookie for authentication (no password in URLs).
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Strip the web root prefix to get the path relative to the dashboard root.
	// Only serve the dashboard at the exact root; return 404 for sub-paths to
	// avoid shadowing the API endpoints registered on the same mux.
	path := strings.TrimPrefix(r.URL.Path, s.webRoot)
	if path != "/" && path != "" {
		http.NotFound(w, r)
		return
	}

	// If not authenticated, show the login page instead of the dashboard.
	// Note: requirePassword does NOT write a 401 response (unless rate-limited),
	// so we can render a friendly HTML login form instead of a bare error.
	if !s.requirePassword(w, r) {
		// If rate-limited, requirePassword already wrote a 429. Check if
		// a response has been started by looking at the status code.
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/html")
			loginTmpl.Execute(w, map[string]string{"WebRoot": s.webRoot})
		}
		return
	}

	// If this was a POST login, redirect to GET to prevent form resubmission
	// on browser refresh (POST-Redirect-GET pattern).
	if r.Method == http.MethodPost {
		http.Redirect(w, r, s.webRoot+"/", http.StatusSeeOther)
		return
	}

	// Render the full dashboard. The cookie is already set, so the client-side
	// JavaScript API calls rely on the cookie for authentication (no password
	// in the URL).
	w.Header().Set("Content-Type", "text/html")
	dashboardTmpl.Execute(w, map[string]string{
		"WebRoot": s.webRoot,
	})
}

// loginTmpl is the HTML template for the login page. Design decisions:
//   - Minimal, centered card layout with no navigation or branding beyond the title.
//   - Dark theme (#0a0a0a background, #1a1a1a card) matching the dashboard aesthetic.
//   - Monospace font stack (SF Mono, Fira Code) for a terminal/ops feel.
//   - Single password field with autofocus for fast keyboard-only login.
//   - Standard HTML form POST (no JavaScript required) for maximum compatibility.
//   - The form action includes {{.WebRoot}} so it works correctly under a reverse proxy prefix.
//   - Cyan (#00cccc) accent color on the title and submit button for brand consistency.
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

// dashboardTmpl is the HTML template for the main dashboard page. Design decisions:
//
// Layout:
//   - Header bar with "TRAPLINE" title and auto-refresh indicator.
//   - Stat cards in a responsive CSS grid (auto-fit, min 150px) showing hosts, findings,
//     critical, and high counts with severity-appropriate colors.
//   - Host list: clickable cards with colored left borders (red=critical, orange=high) and
//     severity badge pills. Clicking a host sets the filter dropdown and reloads findings.
//   - Host dropdown: <select> element for programmatic host filtering.
//   - Findings list: cards with colored left borders by severity, showing severity badge,
//     summary text, and metadata line (hostname / module / finding_id / hit count / last seen).
//
// CSS:
//   - Dark theme: #0a0a0a body, #1a1a1a cards, #222 borders. No light mode.
//   - Severity colors: #ff0000 critical, #cc4400 high, #aa8800 medium, #444 info.
//   - Accent color: #00cccc (cyan) for the title and host stat cards.
//   - Monospace font stack: SF Mono, Fira Code, system monospace.
//   - All spacing uses rem units for accessibility (respects browser font size).
//
// JavaScript:
//   - No framework dependencies -- vanilla JS with fetch() and DOM manipulation.
//   - BASE is injected from the Go template variable at render time.
//   - api() helper sends requests with credentials: 'same-origin' so the
//     session cookie is included automatically. No password in URLs.
//   - load() fetches stats, hosts, and findings in parallel via Promise.all().
//   - Auto-refresh: setInterval(load, 30000) polls every 30 seconds.
//   - esc() function: Creates a temporary DOM element and uses textContent/innerHTML
//     to safely escape HTML entities, preventing XSS from finding summaries.
//   - selectHost() and filterHost(): Client-side host filtering. Sets the dropdown
//     value and re-fetches findings with the ?host= query parameter.
//   - renderHosts() dynamically populates both the host list cards and the
//     <select> dropdown options from the same data, keeping them in sync.
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

async function api(path) {
  const res = await fetch(BASE + path, {credentials: 'same-origin'});
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
