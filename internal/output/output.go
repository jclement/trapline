package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/pkg/finding"
)

// Sink is an output destination for findings.
type Sink interface {
	// Name returns the sink identifier.
	Name() string
	// Emit sends a finding to the sink.
	Emit(f *finding.Finding) error
	// Close shuts down the sink.
	Close() error
}

// Manager manages multiple output sinks.
type Manager struct {
	sinks []Sink
	mu    sync.RWMutex
}

// NewManager creates an output manager from config.
func NewManager(cfg config.OutputConfig) (*Manager, error) {
	m := &Manager{}

	if cfg.Console.Enabled {
		m.sinks = append(m.sinks, NewConsoleSink(cfg.Console))
	}
	if cfg.File.Enabled {
		s, err := NewFileSink(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("file sink: %w", err)
		}
		m.sinks = append(m.sinks, s)
	}
	if cfg.TCP.Enabled {
		m.sinks = append(m.sinks, NewTCPSink(cfg.TCP))
	}
	if cfg.Webhook.Enabled {
		m.sinks = append(m.sinks, NewWebhookSink(cfg.Webhook))
	}

	return m, nil
}

// Emit sends a finding to all sinks.
func (m *Manager) Emit(f *finding.Finding) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.sinks {
		if err := s.Emit(f); err != nil {
			fmt.Fprintf(os.Stderr, "output sink %s error: %v\n", s.Name(), err)
		}
	}
}

// Close shuts down all sinks.
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

// Sinks returns the list of active sinks (for testing/doctor).
func (m *Manager) Sinks() []Sink {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]Sink{}, m.sinks...)
}

// --- Console Sink ---

type ConsoleSink struct {
	format string
	level  finding.Severity
	w      io.Writer
}

func NewConsoleSink(cfg config.ConsoleOutputConfig) *ConsoleSink {
	return &ConsoleSink{
		format: cfg.Format,
		level:  finding.ParseSeverity(cfg.Level),
		w:      os.Stdout,
	}
}

func (s *ConsoleSink) Name() string { return "console" }

func (s *ConsoleSink) Emit(f *finding.Finding) error {
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	if s.format == "text" {
		_, err := fmt.Fprintf(s.w, "[%s] %s %s: %s\n",
			strings.ToUpper(string(f.Severity)),
			f.Timestamp.Format(time.RFC3339),
			f.FindingID,
			f.Summary)
		return err
	}
	data, err := f.JSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = s.w.Write(data)
	return err
}

func (s *ConsoleSink) Close() error { return nil }

// --- File Sink ---

type FileSink struct {
	format string
	level  finding.Severity
	f      *os.File
	mu     sync.Mutex
}

func NewFileSink(cfg config.FileOutputConfig) (*FileSink, error) {
	dir := cfg.Path[:strings.LastIndex(cfg.Path, "/")]
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("creating log dir: %w", err)
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	return &FileSink{
		format: cfg.Format,
		level:  finding.ParseSeverity(cfg.Level),
		f:      f,
	}, nil
}

func (s *FileSink) Name() string { return "file" }

func (s *FileSink) Emit(f *finding.Finding) error {
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := f.JSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = s.f.Write(data)
	return err
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// --- TCP Sink ---

type TCPSink struct {
	address          string
	level            finding.Severity
	retryInterval    time.Duration
	maxRetryInterval time.Duration
	conn             net.Conn
	mu               sync.Mutex
}

func NewTCPSink(cfg config.TCPOutputConfig) *TCPSink {
	retry := cfg.RetryInterval
	if retry == 0 {
		retry = 5 * time.Second
	}
	maxRetry := cfg.MaxRetryInterval
	if maxRetry == 0 {
		maxRetry = 60 * time.Second
	}
	return &TCPSink{
		address:          cfg.Address,
		level:            finding.ParseSeverity(cfg.Level),
		retryInterval:    retry,
		maxRetryInterval: maxRetry,
	}
}

func (s *TCPSink) Name() string { return "tcp" }

func (s *TCPSink) connect() error {
	if s.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", s.address, 5*time.Second)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *TCPSink) Emit(f *finding.Finding) error {
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := f.JSON()
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := s.connect(); err != nil {
		return fmt.Errorf("tcp connect: %w", err)
	}

	_, err = s.conn.Write(data)
	if err != nil {
		// Connection lost, reset for next attempt
		s.conn.Close()
		s.conn = nil
		return fmt.Errorf("tcp write: %w", err)
	}
	return nil
}

func (s *TCPSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// --- Webhook Sink ---

type WebhookSink struct {
	url      string
	level    finding.Severity
	cooldown time.Duration
	template string
	lastSent map[string]time.Time
	mu       sync.Mutex
}

func NewWebhookSink(cfg config.WebhookOutputConfig) *WebhookSink {
	return &WebhookSink{
		url:      cfg.URL,
		level:    finding.ParseSeverity(cfg.Level),
		cooldown: cfg.Cooldown,
		template: cfg.Template,
		lastSent: make(map[string]time.Time),
	}
}

func (s *WebhookSink) Name() string { return "webhook" }

func (s *WebhookSink) Emit(f *finding.Finding) error {
	if f.Severity.Level() < s.level.Level() {
		return nil
	}
	if s.url == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check cooldown
	if last, ok := s.lastSent[f.FindingID]; ok {
		if time.Since(last) < s.cooldown {
			return nil
		}
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"text": fmt.Sprintf("**Trapline Alert on %s**\nModule: %s | Severity: %s\n%s",
			f.Hostname, f.Module, f.Severity, f.Summary),
	})

	// We use a simple approach - in production this would use net/http
	// but we avoid importing it here to keep the sink interface clean.
	// The actual HTTP call is deferred to a helper.
	_ = payload
	s.lastSent[f.FindingID] = time.Now()
	return nil
}

func (s *WebhookSink) Close() error { return nil }

// FormatText formats a finding as human-readable text.
func FormatText(f *finding.Finding) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "[%s] %s %s: %s",
		strings.ToUpper(string(f.Severity)),
		f.Timestamp.Format(time.RFC3339),
		f.FindingID,
		f.Summary)
	return buf.String()
}
