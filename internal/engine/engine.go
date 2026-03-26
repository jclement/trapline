// Package engine is the central orchestrator for the Trapline security scanning system.
//
// The engine is responsible for:
//
//   - Module lifecycle management: registering, initializing, and running scanner modules.
//   - Parallel scheduling: each enabled module runs in its own goroutine on a configurable
//     ticker interval. Modules execute concurrently and independently; a failure or panic
//     in one module does not affect the others.
//   - Finding enrichment: every finding produced by a module is enriched with metadata
//     before delivery -- the local hostname, a UTC timestamp (if the module did not set one),
//     the originating module name, the Trapline version string, and a per-scan random ID
//     that groups all findings from a single scan cycle together.
//   - Finding deduplication via cooldown map: the engine maintains an in-memory map keyed
//     by "module:findingID". If the same finding was already emitted within the configured
//     cooldown window, it is silently suppressed. This prevents alert fatigue when a module
//     repeatedly discovers the same issue across consecutive scan cycles.
//   - Cooldown map pruning: to prevent unbounded memory growth over long-running processes,
//     the cooldown map is pruned whenever it exceeds 10,000 entries. Pruning deletes all
//     entries older than 24 hours, keeping the map bounded in practice.
//   - Panic recovery: each module's scan cycle is wrapped in a deferred recover() so that
//     a panicking module logs an error to stderr and continues on the next tick rather than
//     crashing the entire engine.
package engine

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/internal/metrics"
	"github.com/jclement/tripline/pkg/finding"
)

// FindingHandler is a callback invoked for each deduplicated, enriched finding produced
// by a module scan. Implementations typically forward the finding to an alerting backend
// (e.g., email, webhook, log file). The handler is called synchronously from the
// module's goroutine, so blocking here delays subsequent scans for that module.
type FindingHandler func(*finding.Finding)

// Engine manages module lifecycle, scheduling, and finding deduplication.
// It is the top-level coordinator: callers register Module implementations,
// call Init to prepare them, and then either Run (long-lived daemon loop)
// or ScanAll (one-shot scan). The zero value is not usable; create one via New.
type Engine struct {
	// cfg holds the global Trapline configuration, including per-module
	// enable/disable flags, scan intervals, and the cooldown duration.
	cfg *config.Config

	// modules maps module name -> Module implementation. Populated by Register.
	modules map[string]Module

	// handler is the callback that receives every non-duplicate finding.
	handler FindingHandler

	// hostname is the machine identifier stamped onto every finding. It is
	// resolved once at construction time from the config or os.Hostname.
	hostname string

	// version is the Trapline release version string embedded into findings.
	version string

	// Metrics collector that records per-module scan duration and finding counts.
	metrics *metrics.Collector

	// cooldowns is the deduplication map. Keys are "module:findingID" and values
	// are the wall-clock time the finding was last emitted. Protected by cooldownMu.
	cooldowns map[string]time.Time

	// cooldownMu guards concurrent access to the cooldowns map. Multiple module
	// goroutines may call isDuplicate simultaneously.
	cooldownMu sync.Mutex

	// cancel is the CancelFunc for the context passed to Run. Calling Stop
	// triggers this to signal all module goroutines to exit.
	cancel context.CancelFunc

	// wg tracks all running module goroutines so that Run and Stop can block
	// until every goroutine has cleanly exited.
	wg sync.WaitGroup
}

// New creates a new Engine with the given configuration, finding handler, and version
// string. The hostname is resolved from cfg.Hostname if set, otherwise from
// os.Hostname. The metrics collector is initialized with a 100-entry ring buffer.
// The cooldown map starts empty and grows as findings are emitted.
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
		metrics:   metrics.New(100),
		cooldowns: make(map[string]time.Time),
	}
}

// Register adds a module to the engine's registry, keyed by the module's Name().
// Registration must happen before Init or Run. If two modules share a name, the
// later registration silently overwrites the earlier one.
func (e *Engine) Register(m Module) {
	e.modules[m.Name()] = m
}

// Init initializes every registered module that is enabled in the configuration.
// Disabled modules are skipped entirely. Each enabled module receives a ModuleConfig
// containing the state directory paths and any module-specific settings from the
// YAML config. If any module's Init returns an error, Init short-circuits and
// returns that error immediately (remaining modules are not initialized).
func (e *Engine) Init() error {
	for name, m := range e.modules {
		// Skip modules the user has not enabled in the config file.
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		// Build the per-module config struct with state and baseline directories.
		modCfg := ModuleConfig{
			StateDir:     e.cfg.StateDir,
			BaselinesDir: e.cfg.StateDir + "/baselines",
		}
		// If the YAML config contains a section for this module, pass its
		// extra key-value settings through to the module.
		if mc, ok := e.cfg.Modules[name]; ok {
			modCfg.Settings = mc.Extra
		}
		if err := m.Init(modCfg); err != nil {
			return fmt.Errorf("initializing module %s: %w", name, err)
		}
	}
	return nil
}

// Run starts the long-lived daemon loop. For each enabled module it spawns a
// dedicated goroutine (via runModule) that scans on a repeating ticker interval.
// Run blocks until the context is cancelled (e.g., via Stop or an external signal).
// The context passed in is wrapped with a cancel function stored on the engine so
// that Stop can trigger a graceful shutdown. All module goroutines are tracked by
// a WaitGroup; Run returns only after every goroutine has exited.
func (e *Engine) Run(ctx context.Context) {
	// Derive a cancellable context so Stop() can signal all goroutines.
	ctx, e.cancel = context.WithCancel(ctx)

	for name, m := range e.modules {
		// Only start goroutines for modules the user has enabled.
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		// Resolve the scan interval for this module from the config (module-level
		// override or global default).
		interval := e.cfg.ModuleInterval(name)
		e.wg.Add(1)
		// Each module gets its own goroutine with independent ticker and panic recovery.
		go e.runModule(ctx, m, interval)
	}

	// Block until all module goroutines have returned (i.e., context cancelled).
	e.wg.Wait()
}

// Stop gracefully shuts down the engine by cancelling the Run context and then
// waiting for all module goroutines to finish their current scan cycle and exit.
// It is safe to call Stop even if Run was never called (cancel will be nil).
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	// Block until every module goroutine has returned.
	e.wg.Wait()
}

// ScanAll runs every enabled module exactly once, in parallel, and returns the
// aggregated findings from all modules. This is used for one-shot CLI scans as
// opposed to the long-lived Run daemon loop.
//
// Parallelism: each module runs in its own goroutine, coordinated by a WaitGroup.
// A mutex protects the shared allFindings slice. Errors are captured via sync.Once
// so only the first module error is returned to the caller -- subsequent errors are
// silently dropped but the goroutines still complete normally.
//
// Unlike the daemon path (Run -> scanAndEmit), ScanAll does NOT enrich or deduplicate
// findings. It returns raw findings directly from the modules.
func (e *Engine) ScanAll(ctx context.Context) ([]finding.Finding, error) {
	var (
		allFindings []finding.Finding // shared accumulator, guarded by mu
		mu          sync.Mutex        // protects allFindings from concurrent appends
		wg          sync.WaitGroup    // tracks one goroutine per enabled module
		firstErr    error             // captures the first error encountered
		errOnce     sync.Once         // ensures only the first error is recorded
	)

	for name, m := range e.modules {
		// Skip disabled modules.
		if !e.cfg.ModuleEnabled(name) {
			continue
		}
		wg.Add(1)
		// Launch a goroutine per module. The module variable is passed as a
		// parameter to avoid the classic closure-over-loop-variable bug.
		go func(mod Module) {
			defer wg.Done()
			findings, err := mod.Scan(ctx)
			if err != nil {
				// Record only the first error; additional errors are discarded.
				errOnce.Do(func() {
					firstErr = fmt.Errorf("module %s: %w", mod.Name(), err)
				})
				return
			}
			// Safely append this module's findings to the shared slice.
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(m)
	}

	// Wait for all module goroutines to complete before returning.
	wg.Wait()
	return allFindings, firstErr
}

// ScanModule runs a single named module once and returns its findings directly,
// without enrichment or deduplication. Returns an error if the module name is
// not registered.
func (e *Engine) ScanModule(ctx context.Context, name string) ([]finding.Finding, error) {
	m, ok := e.modules[name]
	if !ok {
		return nil, fmt.Errorf("unknown module: %s", name)
	}
	return m.Scan(ctx)
}

// RebaselineAll iterates over all enabled modules and calls Rebaseline on each one
// sequentially. This captures the current system state as the new known-good baseline
// so that subsequent scans only report changes relative to this point. If any module
// fails, the function returns immediately without rebaselining the remaining modules.
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

// RebaselineModule rebaselines a single named module, capturing its current state
// as the new known-good baseline. Returns an error if the module is not registered.
func (e *Engine) RebaselineModule(ctx context.Context, name string) error {
	m, ok := e.modules[name]
	if !ok {
		return fmt.Errorf("unknown module: %s", name)
	}
	return m.Rebaseline(ctx)
}

// Modules returns the names of all registered modules (both enabled and disabled).
// The order is non-deterministic because the underlying storage is a map.
func (e *Engine) Modules() []string {
	names := make([]string, 0, len(e.modules))
	for name := range e.modules {
		names = append(names, name)
	}
	return names
}

// EnabledModules returns only the names of modules that are enabled in the current
// configuration. Useful for status displays and health checks.
func (e *Engine) EnabledModules() []string {
	var names []string
	for name := range e.modules {
		if e.cfg.ModuleEnabled(name) {
			names = append(names, name)
		}
	}
	return names
}

// runModule is the goroutine lifecycle for a single module in daemon mode.
//
// Lifecycle:
//  1. The goroutine decrements the engine's WaitGroup when it returns (defer wg.Done).
//  2. It performs an immediate scan on startup so that findings are available without
//     waiting for the first ticker interval to elapse.
//  3. It then enters a select loop, scanning on each ticker tick and exiting when
//     the context is cancelled.
//
// Panic recovery: each call to scanAndEmit is wrapped in a closure with a deferred
// recover(). If a module panics during a scan, the panic is caught, an error is
// logged to stderr, and the goroutine continues to the next tick. This prevents a
// single misbehaving module from bringing down the entire engine.
func (e *Engine) runModule(ctx context.Context, m Module, interval time.Duration) {
	// Ensure the WaitGroup is decremented when this goroutine exits,
	// allowing Run() and Stop() to unblock.
	defer e.wg.Done()

	// runScan wraps a single scan cycle with panic recovery. The deferred
	// recover catches any panic from the module's Scan implementation and
	// logs it rather than crashing the process.
	runScan := func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "module %s panic: %v\n", m.Name(), r)
			}
		}()
		e.scanAndEmit(ctx, m)
	}

	// Run the first scan immediately so findings are available right away,
	// without waiting for the first ticker interval to elapse.
	runScan()

	// Create a ticker that fires at the configured interval for this module.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Main loop: scan on each tick, exit when context is cancelled.
	for {
		select {
		case <-ctx.Done():
			// Context cancelled (Stop was called or parent context expired).
			// Exit the goroutine cleanly.
			return
		case <-ticker.C:
			// Time for the next scan cycle.
			runScan()
		}
	}
}

// Metrics returns the engine's metrics collector, which tracks per-module scan
// durations and finding counts in a fixed-size ring buffer.
func (e *Engine) Metrics() *metrics.Collector {
	return e.metrics
}

// scanAndEmit executes a single scan cycle for one module, then enriches and
// deduplicates each resulting finding before passing it to the handler.
//
// Flow:
//  1. Generate a random scan ID (8 hex characters) to correlate all findings
//     from this scan cycle.
//  2. Call the module's Scan method, timing the duration.
//  3. Record the scan metrics (module name, duration, finding count).
//  4. If the scan returned an error, log it to stderr and return early.
//  5. For each finding:
//     a. Enrich: set Hostname, Timestamp (if unset), Module, TraplineVersion, ScanID.
//     b. Deduplicate: check the cooldown map; skip if this finding was already
//     emitted within the configured cooldown window.
//     c. Deliver: call the FindingHandler callback if one is registered.
func (e *Engine) scanAndEmit(ctx context.Context, m Module) {
	// Generate a unique ID for this scan cycle so downstream consumers can
	// group findings that were discovered together.
	scanID := randomID()

	// Time the scan so we can record performance metrics.
	start := time.Now()
	findings, err := m.Scan(ctx)
	duration := time.Since(start)

	// Record metrics regardless of success or failure -- a slow scan that
	// errors is still useful data for operators.
	e.metrics.Record(m.Name(), duration, len(findings))

	if err != nil {
		// Log the error and bail; do not attempt to process partial results.
		fmt.Fprintf(os.Stderr, "module %s scan error: %v\n", m.Name(), err)
		return
	}

	// Process each finding: enrich with metadata, deduplicate, and deliver.
	for i := range findings {
		// Use a pointer into the slice to avoid copying the struct.
		f := &findings[i]

		// --- Enrichment ---
		// Stamp the hostname so findings can be attributed to this machine
		// in a multi-host deployment.
		f.Hostname = e.hostname
		// Only set the timestamp if the module didn't provide one, preserving
		// module-supplied precision when available.
		if f.Timestamp.IsZero() {
			f.Timestamp = time.Now().UTC()
		}
		// Tag with the originating module name for filtering and routing.
		f.Module = m.Name()
		// Embed the Trapline version for debugging and compatibility tracking.
		f.TraplineVersion = e.version
		// Link this finding to the current scan cycle.
		f.ScanID = scanID

		// --- Deduplication ---
		// Check the cooldown map. If this exact finding (same module + findingID)
		// was already emitted within the cooldown window, skip it to avoid
		// flooding the alert pipeline with repeated notifications.
		if e.isDuplicate(f) {
			continue
		}

		// --- Delivery ---
		// Pass the enriched, non-duplicate finding to the registered handler.
		if e.handler != nil {
			e.handler(f)
		}
	}
}

// isDuplicate checks whether the given finding has already been emitted within the
// configured cooldown window. It is safe for concurrent use from multiple module
// goroutines.
//
// Cooldown logic:
//   - The dedup key is "module:findingID", which uniquely identifies a specific
//     finding from a specific module.
//   - If the key exists in the cooldown map and the elapsed time since the last
//     emission is less than cfg.Defaults.Cooldown, the finding is considered a
//     duplicate and true is returned.
//   - Otherwise the finding is fresh (or the cooldown has expired), so the map
//     entry is updated to the current time and false is returned.
//
// Map pruning:
//   - After recording a new entry, if the map has grown beyond 10,000 entries,
//     a full sweep deletes all entries older than 24 hours. This prevents
//     unbounded memory growth in long-running deployments that scan many
//     distinct resources. The 10,000-entry threshold avoids pruning on every
//     call, amortizing the cost across many insertions.
func (e *Engine) isDuplicate(f *finding.Finding) bool {
	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()

	// Build the dedup key from module name and the module-assigned finding ID.
	key := f.Module + ":" + f.FindingID

	// Check if this finding was emitted recently (within the cooldown window).
	if last, ok := e.cooldowns[key]; ok {
		if time.Since(last) < e.cfg.Defaults.Cooldown {
			// Still within cooldown -- suppress this finding.
			return true
		}
	}

	// Either first time seeing this finding or cooldown has expired.
	// Record the current time as the latest emission timestamp.
	e.cooldowns[key] = time.Now()

	// Prevent unbounded growth: if the map exceeds 10,000 entries, prune
	// all entries that are older than 24 hours. This is a simple stop-the-world
	// sweep but is infrequent enough (only when the map is large) to be
	// acceptable in practice.
	if len(e.cooldowns) > 10000 {
		cutoff := time.Now().Add(-24 * time.Hour)
		for k, t := range e.cooldowns {
			if t.Before(cutoff) {
				delete(e.cooldowns, k)
			}
		}
	}

	return false
}

// randomID generates a short random identifier (8 hex characters / 4 bytes of entropy)
// used as the scan ID to correlate findings from the same scan cycle. It uses
// crypto/rand for unpredictability, though collision resistance is not critical here
// since scan IDs are scoped to a single engine instance.
func randomID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
