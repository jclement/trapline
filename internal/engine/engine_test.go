package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/pkg/finding"
)

// mockModule is a test implementation of the Module interface.
type mockModule struct {
	name      string
	initErr   error
	scanErr   error
	findings  []finding.Finding
	scanCount atomic.Int32
}

func (m *mockModule) Name() string { return m.name }

func (m *mockModule) Init(cfg ModuleConfig) error {
	return m.initErr
}

func (m *mockModule) Scan(ctx context.Context) ([]finding.Finding, error) {
	m.scanCount.Add(1)
	if m.scanErr != nil {
		return nil, m.scanErr
	}
	return m.findings, nil
}

func (m *mockModule) Rebaseline(ctx context.Context) error {
	return nil
}

func testConfig() *config.Config {
	return &config.Config{
		StateDir: "/tmp/trapline-test",
		Defaults: config.DefaultsConfig{
			Interval: 100 * time.Millisecond,
			Cooldown: time.Hour,
		},
		Modules: map[string]config.ModuleConfig{
			"test-module": {Enabled: true, Interval: 100 * time.Millisecond},
		},
	}
}

func TestEngineRegisterAndInit(t *testing.T) {
	cfg := testConfig()
	e := New(cfg, nil, "0.1.0")

	m := &mockModule{name: "test-module"}
	e.Register(m)

	if err := e.Init(); err != nil {
		t.Fatalf("Init() error: %v", err)
	}

	modules := e.Modules()
	if len(modules) != 1 {
		t.Errorf("Modules() count = %d, want 1", len(modules))
	}
}

func TestEngineInitError(t *testing.T) {
	cfg := testConfig()
	e := New(cfg, nil, "0.1.0")

	m := &mockModule{name: "test-module", initErr: context.DeadlineExceeded}
	e.Register(m)

	if err := e.Init(); err == nil {
		t.Error("expected Init() error")
	}
}

func TestEngineScanAll(t *testing.T) {
	cfg := testConfig()

	var received []finding.Finding
	var mu sync.Mutex
	handler := func(f *finding.Finding) {
		mu.Lock()
		received = append(received, *f)
		mu.Unlock()
	}

	e := New(cfg, handler, "0.1.0")
	m := &mockModule{
		name: "test-module",
		findings: []finding.Finding{
			{
				FindingID: "test-1",
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   "test finding",
			},
		},
	}
	e.Register(m)
	if err := e.Init(); err != nil {
		t.Fatal(err)
	}

	findings, err := e.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll() error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("ScanAll() returned %d findings, want 1", len(findings))
	}
}

func TestEngineScanModule(t *testing.T) {
	cfg := testConfig()
	e := New(cfg, nil, "0.1.0")

	m := &mockModule{
		name: "test-module",
		findings: []finding.Finding{
			{FindingID: "test-1", Severity: finding.SeverityHigh, Summary: "found it"},
		},
	}
	e.Register(m)
	if err := e.Init(); err != nil {
		t.Fatal(err)
	}

	findings, err := e.ScanModule(context.Background(), "test-module")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

func TestEngineScanModuleUnknown(t *testing.T) {
	cfg := testConfig()
	e := New(cfg, nil, "0.1.0")

	_, err := e.ScanModule(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for unknown module")
	}
}

func TestEngineRunAndStop(t *testing.T) {
	cfg := testConfig()
	cfg.Defaults.Cooldown = 0 // no dedup for this test

	var count atomic.Int32
	handler := func(f *finding.Finding) {
		count.Add(1)
	}

	e := New(cfg, handler, "0.1.0")
	m := &mockModule{
		name: "test-module",
		findings: []finding.Finding{
			{FindingID: "run-test", Severity: finding.SeverityInfo, Summary: "tick"},
		},
	}
	e.Register(m)
	if err := e.Init(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)

	// Wait for at least 2 scan cycles
	time.Sleep(350 * time.Millisecond)
	cancel()
	e.Stop()

	if m.scanCount.Load() < 2 {
		t.Errorf("expected at least 2 scans, got %d", m.scanCount.Load())
	}
}

func TestEngineDeduplication(t *testing.T) {
	cfg := testConfig()
	cfg.Defaults.Cooldown = time.Hour // long cooldown

	var count atomic.Int32
	handler := func(f *finding.Finding) {
		count.Add(1)
	}

	e := New(cfg, handler, "0.1.0")
	m := &mockModule{
		name: "test-module",
		findings: []finding.Finding{
			{FindingID: "dedup-test", Severity: finding.SeverityHigh, Summary: "same"},
		},
	}
	e.Register(m)
	if err := e.Init(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// Scan the same finding multiple times
	e.scanAndEmit(ctx, m)
	e.scanAndEmit(ctx, m)
	e.scanAndEmit(ctx, m)

	if count.Load() != 1 {
		t.Errorf("expected 1 emitted finding (dedup), got %d", count.Load())
	}
}

func TestEngineDisabledModule(t *testing.T) {
	cfg := testConfig()
	cfg.Modules["disabled-mod"] = config.ModuleConfig{Enabled: false}

	e := New(cfg, nil, "0.1.0")
	m := &mockModule{name: "disabled-mod"}
	e.Register(m)
	if err := e.Init(); err != nil {
		t.Fatal(err)
	}

	enabled := e.EnabledModules()
	for _, name := range enabled {
		if name == "disabled-mod" {
			t.Error("disabled module should not appear in EnabledModules()")
		}
	}
}

func TestEngineRebaseline(t *testing.T) {
	cfg := testConfig()
	e := New(cfg, nil, "0.1.0")

	m := &mockModule{name: "test-module"}
	e.Register(m)
	if err := e.Init(); err != nil {
		t.Fatal(err)
	}

	if err := e.RebaselineAll(context.Background()); err != nil {
		t.Fatalf("RebaselineAll() error: %v", err)
	}

	if err := e.RebaselineModule(context.Background(), "test-module"); err != nil {
		t.Fatalf("RebaselineModule() error: %v", err)
	}

	if err := e.RebaselineModule(context.Background(), "nonexistent"); err == nil {
		t.Error("expected error for unknown module")
	}
}

func TestEngineHostname(t *testing.T) {
	cfg := testConfig()
	cfg.Hostname = "custom-host"

	var received *finding.Finding
	handler := func(f *finding.Finding) {
		received = f
	}

	e := New(cfg, handler, "0.1.0")
	m := &mockModule{
		name: "test-module",
		findings: []finding.Finding{
			{FindingID: "host-test", Severity: finding.SeverityInfo, Summary: "test"},
		},
	}
	e.Register(m)
	if err := e.Init(); err != nil { t.Fatal(err) }

	e.scanAndEmit(context.Background(), m)

	if received == nil {
		t.Fatal("expected a finding")
	}
	if received.Hostname != "custom-host" {
		t.Errorf("Hostname = %q, want custom-host", received.Hostname)
	}
}

func TestRandomID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := randomID()
		if len(id) != 8 {
			t.Errorf("randomID() length = %d, want 8", len(id))
		}
		if ids[id] {
			t.Errorf("duplicate randomID: %s", id)
		}
		ids[id] = true
	}
}
