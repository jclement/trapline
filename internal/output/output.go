// Package output implements a multi-sink output architecture for dispatching
// security findings to one or more destinations simultaneously.
//
// # Architecture
//
// The central type is [Manager], which holds a collection of [Sink] implementations
// and fans out each finding to every registered sink. Sinks are added at startup
// based on the user's OutputConfig, and optionally at runtime via
// [Manager.AddDashboardSink]. The Manager is safe for concurrent use; it holds a
// read-write mutex so that Emit (read path) does not block other Emit calls, while
// sink registration (write path) is serialized.
//
// # Sink Types
//
//   - [ConsoleSink] writes findings to stdout in either human-readable text or
//     newline-delimited JSON. It is the primary sink during interactive use and
//     supports per-sink severity-level filtering so operators can suppress low-
//     priority noise on the terminal while still logging everything to file.
//
//   - [FileSink] appends JSON-encoded findings to a log file on disk. It
//     implements size-based log rotation: when the file exceeds maxSizeMB, the
//     current file is renamed to .1, previous .1 becomes .2, and so on up to
//     maxBackups. The oldest backup beyond that limit is removed. Rotation is
//     checked on every Emit call while holding the sink mutex.
//
//   - [TCPSink] streams newline-delimited JSON over a persistent TCP connection
//     to a remote log collector (e.g. Logstash, Splunk HEC, or a custom
//     receiver). If the connection is down, findings are stored in an in-memory
//     ring buffer (capped at [tcpBufferMax] = 1000 entries). On the next
//     successful connect the buffer is flushed before the new finding is sent,
//     preserving ordering. Reconnection is attempted on every Emit; there is no
//     background retry goroutine, keeping the design simple and deterministic.
//
//   - [WebhookSink] fires an HTTP POST (JSON body) to a configured URL, useful
//     for Slack/Teams/Discord incoming-webhook integrations. It tracks a per-
//     finding-ID cooldown so that repeated firings of the same rule do not spam
//     the channel.
//
//   - [DashboardSink] batches findings and POSTs them to the Trapline dashboard
//     API (/api/findings). Findings accumulate in a slice and are flushed in
//     groups of 10 to amortize HTTP overhead. Any remaining findings are flushed
//     on Close. Requests carry an Authorization: Bearer header for server-side
//     authentication.
//
// # Level Filtering
//
// Every sink that accepts a Level configuration (console, file, TCP, webhook)
// compares the finding's severity against its configured minimum level at the
// top of Emit. Findings below the threshold are silently dropped for that sink
// only -- other sinks with a lower threshold still receive them.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/internal/tui"
	"github.com/jclement/tripline/pkg/finding"
)

// Sink is the interface that all output destinations must implement.
// Each sink has a human-readable name (used in error messages), an Emit method
// that delivers a single finding, and a Close method for graceful shutdown.
type Sink interface {
	// Name returns a short, human-readable identifier for this sink (e.g.
	// "console", "file", "tcp"). It is used in error messages when an Emit
	// or Close call fails.
	Name() string

	// Emit delivers a single finding to the output destination. Implementations
	// must be safe for concurrent use if the Manager may call Emit from multiple
	// goroutines. Returning a non-nil error does not stop dispatch to other
	// sinks -- the Manager logs the error to stderr and continues.
	Emit(f *finding.Finding) error

	// Close performs any cleanup required by the sink, such as closing file
	// handles, flushing buffered data, or terminating network connections.
	// It is called exactly once during Manager.Close.
	Close() error
}

// Manager is the top-level dispatcher that fans out findings to every
// registered Sink. It is safe for concurrent use: Emit acquires a read lock
// so multiple goroutines can emit simultaneously, while AddDashboardSink and
// Close acquire a write lock to mutate the sink list.
type Manager struct {
	sinks []Sink       // all registered output sinks, in registration order
	mu    sync.RWMutex // guards sinks slice; RLock for reads, Lock for writes
}

// NewManager creates an output Manager and initialises sinks based on the
// provided OutputConfig. Each sink type is only created if its Enabled flag is
// true. An error is returned if any sink fails to initialise (e.g. the file
// sink cannot create its log directory).
func NewManager(cfg config.OutputConfig) (*Manager, error) {
	m := &Manager{}

	// Console sink -- writes to stdout in text or JSON format.
	if cfg.Console.Enabled {
		m.sinks = append(m.sinks, NewConsoleSink(cfg.Console))
	}
	// File sink -- appends JSON to a log file with optional rotation.
	if cfg.File.Enabled {
		s, err := NewFileSink(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("file sink: %w", err)
		}
		m.sinks = append(m.sinks, s)
	}
	// TCP sink -- streams newline-delimited JSON over a persistent TCP connection.
	if cfg.TCP.Enabled {
		m.sinks = append(m.sinks, NewTCPSink(cfg.TCP))
	}
	// Webhook sink -- HTTP POSTs a formatted alert to a webhook URL.
	if cfg.Webhook.Enabled {
		m.sinks = append(m.sinks, NewWebhookSink(cfg.Webhook))
	}

	return m, nil
}

// AddDashboardSink dynamically registers a DashboardSink that POSTs batched
// findings to the Trapline dashboard server. Both url and secret must be
// non-empty; if either is blank the call is a no-op. This method is safe for
// concurrent use and may be called after NewManager.
func (m *Manager) AddDashboardSink(url, secret string) {
	if url == "" || secret == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sinks = append(m.sinks, NewDashboardSink(url, secret))
}

// Emit dispatches a finding to every registered sink sequentially. If any sink
// returns an error, the error is logged to stderr and dispatch continues to the
// remaining sinks -- a single failing sink never prevents delivery to the
// others. A read lock is held for the duration, so multiple goroutines may call
// Emit concurrently without blocking each other.
func (m *Manager) Emit(f *finding.Finding) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sinks {
		if err := s.Emit(f); err != nil {
			// Log to stderr rather than returning an error so that one broken
			// sink does not prevent delivery to the remaining sinks.
			fmt.Fprintf(os.Stderr, "output sink %s error: %v\n", s.Name(), err)
		}
	}
}

// Close shuts down every registered sink by calling its Close method. Errors
// are collected and returned as a single joined error string. A write lock is
// held to prevent concurrent Emit calls during shutdown.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []string
	for _, s := range m.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", s.Name(), err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("closing sinks: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Sinks returns a shallow copy of the active sink list. This is primarily used
// by tests and the "doctor" diagnostic command to inspect which sinks are
// configured.
func (m *Manager) Sinks() []Sink {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Return a copy so the caller cannot mutate the internal slice.
	return append([]Sink{}, m.sinks...)
}

// ---------------------------------------------------------------------------
// Console Sink
// ---------------------------------------------------------------------------

// ConsoleSink writes findings to an io.Writer (typically os.Stdout). It
// supports two output formats controlled by the "format" field:
//
//   - "text": a single human-readable line per finding in the form
//     [SEVERITY] <RFC3339 timestamp> <FindingID>: <Summary>
//   - any other value (including "json"): the finding serialised as compact
//     JSON followed by a newline, suitable for piping into jq or other tools.
//
// Findings whose severity is below the configured minimum level are silently
// dropped.
type ConsoleSink struct {
	format string           // "text" for human-readable output, anything else for JSON
	level  finding.Severity // minimum severity threshold; lower-severity findings are dropped
	w      io.Writer        // output destination, defaults to os.Stdout
}

// NewConsoleSink creates a ConsoleSink from the console section of the output
// config. The format defaults to JSON if not explicitly set to "text". The
// level string is parsed into a Severity; unrecognised values map to the
// lowest severity so that all findings pass through.
func NewConsoleSink(cfg config.ConsoleOutputConfig) *ConsoleSink {
	return &ConsoleSink{
		format: cfg.Format,
		level:  finding.ParseSeverity(cfg.Level),
		w:      os.Stdout,
	}
}

// Name returns "console", used for error reporting.
func (s *ConsoleSink) Name() string { return "console" }

// Emit writes a single finding to the console. If the finding's severity is
// below the sink's configured level, it is silently skipped. In "text" mode
// the output is a bracketed severity tag followed by an RFC 3339 timestamp,
// the finding ID, and the summary on one line. In JSON mode the finding is
// serialised via its own JSON() method and terminated with a newline.
func (s *ConsoleSink) Emit(f *finding.Finding) error {
	// Level filter: drop findings below the configured minimum severity.
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	if s.format == "text" {
		// Use colored log-style output when writing to a TTY.
		if tui.IsTTY() {
			badge := tui.SeverityBadge(f.Severity)
			ts := tui.Dimmed.Render(f.Timestamp.Format("15:04:05"))
			hash := ""
			if f.ScanID != "" {
				hash = tui.Dimmed.Render(f.ScanID) + " "
			}
			id := tui.Dimmed.Render(f.FindingID)
			_, err := fmt.Fprintf(s.w, "%s %s %s%s  %s\n",
				ts, badge, hash, f.Summary, id)
			return err
		}
		// Plain text fallback for pipes/non-TTY.
		_, err := fmt.Fprintf(s.w, "[%s] %s %s: %s\n",
			strings.ToUpper(string(f.Severity)),
			f.Timestamp.Format(time.RFC3339),
			f.FindingID,
			f.Summary)
		return err
	}
	// JSON format: compact, one JSON object per line (NDJSON).
	data, err := f.JSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = s.w.Write(data)
	return err
}

// Close is a no-op for ConsoleSink because os.Stdout is not owned by this sink.
func (s *ConsoleSink) Close() error { return nil }

// ---------------------------------------------------------------------------
// File Sink
// ---------------------------------------------------------------------------

// FileSink appends newline-delimited JSON findings to a log file with optional
// size-based rotation. When the file size exceeds maxSizeMB, the sink performs
// a synchronous rotation: existing backups are shifted (e.g. .1 becomes .2,
// .2 becomes .3) up to maxBackups, the oldest beyond that limit is removed,
// and a fresh file is opened. All file operations are serialised by mu so that
// concurrent Emit calls do not interleave writes or race on rotation.
type FileSink struct {
	format     string           // output format (currently always JSON)
	level      finding.Severity // minimum severity threshold
	f          *os.File         // open file handle for the current log file
	path       string           // canonical path to the log file (without .N suffix)
	maxSizeMB  int              // file size threshold in megabytes that triggers rotation; 0 disables rotation
	maxBackups int              // maximum number of rotated backup files to keep (default 5)
	mu         sync.Mutex       // serialises writes and rotation
}

// NewFileSink creates a FileSink that writes to the path specified in cfg.
// The parent directory is created with mode 0750 if it does not exist. The
// file is opened in append mode with permissions 0640. maxBackups defaults to
// 5 if not set in the config.
func NewFileSink(cfg config.FileOutputConfig) (*FileSink, error) {
	// Extract the directory portion of the path so we can ensure it exists.
	dir := cfg.Path[:strings.LastIndex(cfg.Path, "/")]
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("creating log dir: %w", err)
	}
	// Open (or create) the log file in append-only mode.
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	maxBackups := cfg.MaxBackups
	if maxBackups == 0 {
		maxBackups = 5 // sensible default: keep up to 5 rotated files
	}
	return &FileSink{
		format:     cfg.Format,
		level:      finding.ParseSeverity(cfg.Level),
		f:          f,
		path:       cfg.Path,
		maxSizeMB:  cfg.MaxSizeMB,
		maxBackups: maxBackups,
	}, nil
}

// Name returns "file", used for error reporting.
func (s *FileSink) Name() string { return "file" }

// Emit serialises the finding as JSON and appends it to the log file. Before
// writing, if maxSizeMB is configured, the current file size is checked via
// Stat. If the file has reached or exceeded the threshold the sink performs a
// synchronous rotation before writing. The finding is always written as a
// single JSON line terminated by a newline.
func (s *FileSink) Emit(f *finding.Finding) error {
	// Level filter: drop findings below the configured minimum severity.
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if rotation is needed by comparing the current file size against
	// the configured maximum. A maxSizeMB of 0 disables rotation entirely.
	if s.maxSizeMB > 0 {
		if info, err := s.f.Stat(); err == nil {
			if info.Size() >= int64(s.maxSizeMB)*1024*1024 {
				s.rotate()
			}
		}
	}

	// Serialise the finding as compact JSON and write it as a single line.
	data, err := f.JSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = s.f.Write(data)
	return err
}

// rotate closes the current file, shifts existing backup files by one position,
// and opens a fresh log file. The shift works from the highest-numbered backup
// down to .1 so that no file is overwritten:
//
//	.maxBackups is deleted (oldest removed)
//	.maxBackups-1 -> .maxBackups
//	...
//	.1 -> .2
//	current -> .1
//	(new empty file opened at s.path)
//
// Must be called with s.mu held. Errors during rename/open are handled on a
// best-effort basis: if the new file cannot be opened, the sink falls back to
// reopening the .1 file so that subsequent writes do not panic on a nil handle.
func (s *FileSink) rotate() {
	s.f.Close()

	// Shift existing backups: .2 -> .3, .1 -> .2, etc.
	// Iterate from highest to lowest so each rename target is free.
	for i := s.maxBackups; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", s.path, i)
		dst := fmt.Sprintf("%s.%d", s.path, i+1)
		if i == s.maxBackups {
			// The oldest allowed backup -- remove it to make room.
			os.Remove(src) // remove oldest
		} else {
			// Shift this backup up by one position.
			os.Rename(src, dst)
		}
	}

	// Rename current log file to the first backup slot (.1).
	os.Rename(s.path, s.path+".1")

	// Open a fresh, empty log file at the original path.
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		// Best effort: reopen the renamed file so we still have a valid handle.
		f, _ = os.OpenFile(s.path+".1", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	}
	s.f = f
}

// Close flushes and closes the underlying file handle. The mutex is held to
// prevent races with any in-flight Emit calls.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// ---------------------------------------------------------------------------
// TCP Sink
// ---------------------------------------------------------------------------

// tcpBufferMax is the maximum number of findings that will be held in the
// in-memory ring buffer while the TCP connection is down. When the buffer is
// full the oldest entry is evicted to make room for the newest, ensuring
// bounded memory usage even during extended outages.
const tcpBufferMax = 1000

// TCPSink streams newline-delimited JSON findings over a persistent TCP
// connection to a remote log collector. If the connection is unavailable,
// findings are buffered in an in-memory ring buffer (up to tcpBufferMax
// entries). On the next successful connection the buffer is flushed before the
// current finding, preserving chronological order.
//
// Reconnection strategy: there is no background reconnect goroutine. Instead,
// each call to Emit checks whether the connection is alive and attempts to
// re-dial if it is nil. This keeps the implementation simple and avoids idle
// goroutines when no findings are being generated. The retryInterval and
// maxRetryInterval fields are stored from config for potential future use by
// a background reconnect loop but are not currently used in the Emit path.
type TCPSink struct {
	address          string           // host:port of the remote TCP endpoint
	level            finding.Severity // minimum severity threshold
	retryInterval    time.Duration    // base interval between reconnection attempts (from config)
	maxRetryInterval time.Duration    // upper bound for exponential backoff (from config)
	conn             net.Conn         // current TCP connection, or nil if disconnected
	buffer           [][]byte         // ring buffer for findings that could not be sent
	mu               sync.Mutex       // serialises connect, write, and buffer operations
}

// NewTCPSink creates a TCPSink from the TCP section of the output config. The
// connection is not established eagerly; it is dialled lazily on the first
// Emit. Default retry intervals are 5 seconds (base) and 60 seconds (max).
func NewTCPSink(cfg config.TCPOutputConfig) *TCPSink {
	retry := cfg.RetryInterval
	if retry == 0 {
		retry = 5 * time.Second // default base retry interval
	}
	maxRetry := cfg.MaxRetryInterval
	if maxRetry == 0 {
		maxRetry = 60 * time.Second // default maximum retry interval
	}
	return &TCPSink{
		address:          cfg.Address,
		level:            finding.ParseSeverity(cfg.Level),
		retryInterval:    retry,
		maxRetryInterval: maxRetry,
	}
}

// Name returns "tcp", used for error reporting.
func (s *TCPSink) Name() string { return "tcp" }

// connect dials the remote TCP endpoint if there is no active connection. It
// uses a 5-second timeout to avoid blocking Emit for too long. Must be called
// with s.mu held.
func (s *TCPSink) connect() error {
	if s.conn != nil {
		return nil // already connected
	}
	conn, err := net.DialTimeout("tcp", s.address, 5*time.Second)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

// Emit serialises the finding as JSON, attempts to send it over the TCP
// connection, and buffers it in the ring buffer if the connection is down.
// On a successful connect, any previously buffered data is flushed first so
// that findings arrive at the collector in chronological order. If a write
// fails (connection lost mid-send), the connection is closed and set to nil
// so that the next Emit will attempt to reconnect.
func (s *TCPSink) Emit(f *finding.Finding) error {
	// Level filter: drop findings below the configured minimum severity.
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Serialise the finding as a single JSON line.
	data, err := f.JSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Attempt to establish or reuse the TCP connection.
	if err := s.connect(); err != nil {
		// Connection failed -- buffer the data for later delivery.
		s.bufferData(data)
		return fmt.Errorf("tcp connect: %w", err)
	}

	// Flush any previously buffered data before sending the current finding,
	// preserving chronological ordering.
	s.flushBuffer()

	// Write the current finding.
	_, err = s.conn.Write(data)
	if err != nil {
		// Connection lost mid-write. Close the dead connection so the next
		// Emit call will attempt to reconnect, and buffer the current data.
		s.conn.Close()
		s.conn = nil
		s.bufferData(data)
		return fmt.Errorf("tcp write: %w", err)
	}
	return nil
}

// bufferData appends a copy of data to the ring buffer. If the buffer has
// reached tcpBufferMax capacity, the oldest entry is evicted (dropped) to
// make room. A copy is made so the caller's slice can be reused safely.
// Must be called with s.mu held.
func (s *TCPSink) bufferData(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	if len(s.buffer) >= tcpBufferMax {
		// Evict the oldest entry to maintain the size cap.
		s.buffer = s.buffer[1:]
	}
	s.buffer = append(s.buffer, cp)
}

// flushBuffer attempts to write every buffered entry to the active TCP
// connection. Entries that fail to send are retained in the buffer for the
// next attempt; successfully sent entries are removed. Must be called with
// s.mu held and s.conn != nil.
func (s *TCPSink) flushBuffer() {
	remaining := s.buffer[:0] // reuse backing array
	for _, data := range s.buffer {
		if _, err := s.conn.Write(data); err != nil {
			// Keep entries that failed to send for the next flush attempt.
			remaining = append(remaining, data)
		}
	}
	s.buffer = remaining
}

// Close shuts down the TCP connection if one is active. Any data still in the
// ring buffer is abandoned (not flushed) because there may not be a valid
// connection.
func (s *TCPSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Webhook Sink
// ---------------------------------------------------------------------------

// WebhookSink delivers findings as HTTP POST requests to an external webhook
// URL (e.g. Slack incoming webhook, Teams connector, or a custom endpoint).
// The JSON payload contains a "text" field with a Markdown-formatted alert
// string. A per-finding-ID cooldown prevents the same alert from being sent
// repeatedly within a short window, which is important for rules that fire on
// every scan cycle.
type WebhookSink struct {
	url      string               // destination webhook URL
	level    finding.Severity     // minimum severity threshold
	cooldown time.Duration        // minimum interval between POSTs for the same FindingID
	template string               // reserved for future custom payload templates
	lastSent map[string]time.Time // tracks the last send time per FindingID for cooldown enforcement
	mu       sync.Mutex           // serialises cooldown map access and HTTP calls
}

// NewWebhookSink creates a WebhookSink from the webhook section of the output
// config. The lastSent map is initialised empty and populated as findings are
// emitted.
func NewWebhookSink(cfg config.WebhookOutputConfig) *WebhookSink {
	return &WebhookSink{
		url:      cfg.URL,
		level:    finding.ParseSeverity(cfg.Level),
		cooldown: cfg.Cooldown,
		template: cfg.Template,
		lastSent: make(map[string]time.Time),
	}
}

// Name returns "webhook", used for error reporting.
func (s *WebhookSink) Name() string { return "webhook" }

// Emit sends a finding to the configured webhook URL via HTTP POST. The
// following checks are performed before sending:
//
//  1. Severity filter: the finding must meet or exceed the sink's level.
//  2. URL guard: if no URL is configured the call is a no-op.
//  3. Cooldown: if the same FindingID was sent within the cooldown window, the
//     finding is silently dropped to avoid flooding the webhook endpoint.
//
// The payload is a JSON object with a single "text" field containing a
// Markdown-formatted alert that includes the hostname, module, severity, and
// summary. A 10-second HTTP client timeout prevents slow endpoints from
// blocking the sink indefinitely.
func (s *WebhookSink) Emit(f *finding.Finding) error {
	// Level filter: drop findings below the configured minimum severity.
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	// Guard: no URL means webhooks are effectively disabled.
	if s.url == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Cooldown check: suppress repeated alerts for the same finding within
	// the configured cooldown window to avoid spamming the webhook target.
	if last, ok := s.lastSent[f.FindingID]; ok {
		if time.Since(last) < s.cooldown {
			return nil
		}
	}

	// Build a Markdown-formatted payload suitable for Slack/Teams/Discord.
	payload, err := json.Marshal(map[string]interface{}{
		"text": fmt.Sprintf("**Trapline Alert on %s**\nModule: %s | Severity: %s\n%s",
			f.Hostname, f.Module, f.Severity, f.Summary),
	})
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	// POST the payload with a conservative 10-second timeout.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(s.url, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	resp.Body.Close()

	// Record the send time so subsequent identical findings are suppressed
	// until the cooldown period elapses.
	s.lastSent[f.FindingID] = time.Now()
	return nil
}

// Close is a no-op for WebhookSink because there are no persistent resources
// to release.
func (s *WebhookSink) Close() error { return nil }

// ---------------------------------------------------------------------------
// Dashboard Sink
// ---------------------------------------------------------------------------

// DashboardSink batches findings and POSTs them as a JSON array to the
// Trapline dashboard server's /api/findings endpoint. Batching amortises HTTP
// overhead: findings accumulate in an internal slice and are flushed to the
// server every 10 findings. Any partial batch remaining at shutdown is flushed
// by Close, ensuring no findings are lost on graceful exit.
//
// Authentication is handled via a Bearer token in the Authorization header,
// using the shared secret configured on the dashboard server.
type DashboardSink struct {
	url    string             // full URL to the /api/findings endpoint
	secret string             // shared secret used as a Bearer token for authentication
	client *http.Client       // reusable HTTP client with a 15-second timeout
	batch  []*finding.Finding // accumulator for findings awaiting flush
	mu     sync.Mutex         // serialises batch append and flush operations
}

// NewDashboardSink creates a DashboardSink that will POST findings to the
// given base URL (with /api/findings appended). The secret is sent as a
// Bearer token in every request. A trailing slash on the URL is stripped
// before appending the API path to avoid double slashes.
func NewDashboardSink(url, secret string) *DashboardSink {
	return &DashboardSink{
		url:    strings.TrimRight(url, "/") + "/api/findings",
		secret: secret,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Name returns "dashboard", used for error reporting.
func (s *DashboardSink) Name() string { return "dashboard" }

// Emit appends a finding to the internal batch. When the batch reaches 10
// findings, it is flushed to the dashboard server via an HTTP POST. If the
// batch has fewer than 10 findings, Emit returns immediately without making
// a network call. This batching strategy reduces HTTP overhead while keeping
// latency bounded (at most 10 findings of delay).
//
// Note: unlike other sinks, DashboardSink does not perform severity-level
// filtering -- all findings are forwarded to the dashboard for centralised
// visibility.
func (s *DashboardSink) Emit(f *finding.Finding) error {
	s.mu.Lock()
	s.batch = append(s.batch, f)
	// Flush every 10 findings to amortise HTTP round-trip overhead.
	if len(s.batch) < 10 {
		s.mu.Unlock()
		return nil
	}
	// Batch is full -- take ownership and release the lock before the
	// potentially slow HTTP call to avoid blocking other Emit callers.
	batch := s.batch
	s.batch = nil
	s.mu.Unlock()

	return s.flush(batch)
}

// flush serialises the batch as a JSON array and POSTs it to the dashboard
// endpoint. The Authorization header carries the shared secret as a Bearer
// token. A non-200 response is treated as an error. This method is safe to
// call without holding s.mu because it operates only on its own batch
// parameter.
func (s *DashboardSink) flush(batch []*finding.Finding) error {
	if len(batch) == 0 {
		return nil
	}

	// Serialise the batch as a JSON array of finding objects.
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	// Build the HTTP request with JSON content type and Bearer auth.
	req, err := http.NewRequest("POST", s.url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.secret)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("dashboard post: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dashboard returned %d", resp.StatusCode)
	}
	return nil
}

// Close flushes any remaining findings in the batch to the dashboard server
// and returns. This ensures that a partial batch (fewer than 10 findings) is
// not silently lost on shutdown.
func (s *DashboardSink) Close() error {
	s.mu.Lock()
	batch := s.batch
	s.batch = nil
	s.mu.Unlock()
	return s.flush(batch)
}

// FormatText formats a finding as a single human-readable line suitable for
// terminal display. The format is:
//
//	[SEVERITY] <RFC3339 timestamp> <FindingID>: <Summary>
//
// This is a standalone utility function used by the ConsoleSink in text mode
// and available for other callers that need a quick textual representation.
func FormatText(f *finding.Finding) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "[%s] %s %s: %s",
		strings.ToUpper(string(f.Severity)),
		f.Timestamp.Format(time.RFC3339),
		f.FindingID,
		f.Summary)
	return buf.String()
}
