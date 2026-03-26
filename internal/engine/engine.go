package engine

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/pkg/finding"
)

// FindingHandler is called for each finding produced by a module.
type FindingHandler func(*finding.Finding)

// Engine manages module lifecycle, scheduling, and finding deduplication.
type Engine struct {
	cfg      *config.Config
	modules  map[string]Module
	handler  FindingHandler
	hostname string
	version  string

	// Deduplication state
	cooldowns map[string]time.Time
	cooldownMu sync.Mutex

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a new engine.
func New(cfg *config.Config, handler FindingHandler, version string) *Engine {
	hostname := cfg.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	return &Engine{
		cfg:       cfg,
		modules:   make(map[string]Module),
		handler:   handler,
		hostname:  hostname,
		version:   version,
		cooldowns: make(map[string]time.Time),
	}
}

// Register adds a module to the engine.
func (e *Engine) Register(m Module) {
	e.modules[m.Name()] = m
}

// Init initializes all enabled modules.
func (e *Engine) Init() error {
	for name, m := range e.modules {
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		modCfg := ModuleConfig{
			StateDir:     e.cfg.StateDir,
			BaselinesDir: e.cfg.StateDir + "/baselines",
		}
		if mc, ok := e.cfg.Modules[name]; ok {
			modCfg.Settings = mc.Extra
		}
		if err := m.Init(modCfg); err != nil {
			return fmt.Errorf("initializing module %s: %w", name, err)
		}
	}
	return nil
}

// Run starts all enabled modules on their configured intervals.
// Blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	ctx, e.cancel = context.WithCancel(ctx)

	for name, m := range e.modules {
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		interval := e.cfg.ModuleInterval(name)
		e.wg.Add(1)
		go e.runModule(ctx, m, interval)
	}

	e.wg.Wait()
}

// Stop gracefully stops the engine.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

// ScanAll runs all enabled modules once and returns all findings.
func (e *Engine) ScanAll(ctx context.Context) ([]finding.Finding, error) {
	var (
		allFindings []finding.Finding
		mu          sync.Mutex
		wg          sync.WaitGroup
		firstErr    error
		errOnce     sync.Once
	)

	for name, m := range e.modules {
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		wg.Add(1)
		go func(mod Module) {
			defer wg.Done()
			findings, err := mod.Scan(ctx)
			if err != nil {
				errOnce.Do(func() {
					firstErr = fmt.Errorf("module %s: %w", mod.Name(), err)
				})
				return
			}
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(m)
	}

	wg.Wait()
	return allFindings, firstErr
}

// ScanModule runs a single module once and returns findings.
func (e *Engine) ScanModule(ctx context.Context, name string) ([]finding.Finding, error) {
	m, ok := e.modules[name]
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}
	return m.Scan(ctx)
}

// RebaselineAll rebaselines all enabled modules.
func (e *Engine) RebaselineAll(ctx context.Context) error {
	for name, m := range e.modules {
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		if err := m.Rebaseline(ctx); err != nil {
			return fmt.Errorf("rebaselining %s: %w", name, err)
		}
	}
	return nil
}

// RebaselineModule rebaselines a single module.
func (e *Engine) RebaselineModule(ctx context.Context, name string) error {
	m, ok := e.modules[name]
	if !ok {
		return fmt.Errorf("unknown module: %s", name)
	}
	return m.Rebaseline(ctx)
}

// Modules returns the list of registered module names.
func (e *Engine) Modules() []string {
	names := make([]string, 0, len(e.modules))
	for name := range e.modules {
		names = append(names, name)
	}
	return names
}

// EnabledModules returns only enabled module names.
func (e *Engine) EnabledModules() []string {
	var names []string
	for name := range e.modules {
		if e.cfg.ModuleEnabled(name) {
			names = append(names, name)
		}
	}
	return names
}

func (e *Engine) runModule(ctx context.Context, m Module, interval time.Duration) {
	defer e.wg.Done()

	// Run immediately on start
	e.scanAndEmit(ctx, m)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.scanAndEmit(ctx, m)
		}
	}
}

func (e *Engine) scanAndEmit(ctx context.Context, m Module) {
	scanID := randomID()
	findings, err := m.Scan(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "module %s scan error: %v\n", m.Name(), err)
		return
	}

	for i := range findings {
		f := &findings[i]
		// Enrich
		f.Hostname = e.hostname
		if f.Timestamp.IsZero() {
			f.Timestamp = time.Now().UTC()
		}
		f.Module = m.Name()
		f.TraplineVersion = e.version
		f.ScanID = scanID

		// Dedup
		if e.isDuplicate(f) {
			continue
		}

		if e.handler != nil {
			e.handler(f)
		}
	}
}

func (e *Engine) isDuplicate(f *finding.Finding) bool {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()

	key := f.Module + ":" + f.FindingID
	if last, ok := e.cooldowns[key]; ok {
		if time.Since(last) < e.cfg.Defaults.Cooldown {
			return true
		}
	}
	e.cooldowns[key] = time.Now()
	return false
}

func randomID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
