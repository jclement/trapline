// Package config handles loading, parsing, and validating the Trapline YAML
// configuration file. It implements a layered configuration strategy: callers
// first obtain a [Default] config containing production-ready defaults, then
// optionally merge user-supplied YAML on top via [Load]. This ensures every
// field has a sensible value even when the user's YAML only overrides a handful
// of keys.
//
// Configuration is read once at startup and treated as immutable for the
// lifetime of the process. The top-level [Config] struct mirrors the on-disk
// YAML structure one-to-one: field names use `yaml:"..."` tags so that Go
// conventions (CamelCase) map cleanly to the snake_case YAML the operator
// edits.
//
// Module configuration deserves special attention. Each scanner module has an
// entry in the Modules map keyed by its well-known name (e.g. "file-integrity",
// "ports"). Modules inherit the global Defaults for interval, severity, and
// cooldown unless overridden per-module. The [ModuleConfig.Extra] field uses
// the ",inline" YAML tag to capture any module-specific keys (e.g. paths to
// watch, severity overrides) without requiring this package to know about every
// module's schema.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level trapline configuration. It is the root struct
// deserialized from /etc/trapline/trapline.yml. Each section governs a
// distinct subsystem: output sinks, the dashboard agent, self-update
// behavior, global defaults for scanner modules, and per-module overrides.
//
// YAML mapping:
//
//	hostname:   override the OS hostname in emitted findings (optional)
//	state_dir:  root directory for baselines and runtime state
//	output:     nested output-sink configuration (console, file, TCP, webhook)
//	dashboard:  agent-to-dashboard reporting endpoint and secret
//	update:     self-update from GitHub Releases
//	defaults:   fallback interval/severity/cooldown for all modules
//	modules:    per-module enable/disable and interval overrides
type Config struct {
	// Hostname overrides the OS hostname attached to every emitted finding.
	// When empty the system hostname is detected at runtime.
	Hostname string `yaml:"hostname"`

	// StateDir is the root directory for persistent state: baselines,
	// lock files, and scanner-specific working data. Must be writable by
	// the trapline process (typically root). The systemd unit grants
	// ReadWritePaths for this directory.
	StateDir string `yaml:"state_dir"`

	// Output configures where findings and log messages are sent.
	Output OutputConfig `yaml:"output"`

	// Dashboard configures the optional agent-to-dashboard reporting channel.
	Dashboard DashboardConfig `yaml:"dashboard"`

	// Update configures the self-update mechanism that polls GitHub Releases.
	Update UpdateConfig `yaml:"update"`

	// Defaults provides fallback values inherited by any module that does not
	// explicitly set its own interval, severity, or cooldown.
	Defaults DefaultsConfig `yaml:"defaults"`

	// Modules maps module names (e.g. "file-integrity", "ports") to their
	// per-module configuration. During [Validate], any enabled module that
	// lacks an explicit interval inherits [Defaults.Interval].
	Modules map[string]ModuleConfig `yaml:"modules"`
}

// OutputConfig configures all output sinks. Trapline supports four output
// channels simultaneously: console (stdout), file (rotated log), TCP (for
// Fluent Bit or similar), and webhook (HTTP POST for alerting). Each sink
// can be independently enabled/disabled and filtered by severity level.
type OutputConfig struct {
	Console ConsoleOutputConfig `yaml:"console"` // stdout — useful for interactive runs and CI
	File    FileOutputConfig    `yaml:"file"`     // rotated log file on disk
	TCP     TCPOutputConfig     `yaml:"tcp"`      // TCP socket — typically Fluent Bit ingestion
	Webhook WebhookOutputConfig `yaml:"webhook"`  // HTTP POST webhook for high-severity alerts
}

// ConsoleOutputConfig configures stdout output. This sink is primarily useful
// during interactive "trapline scan" runs. In daemon mode, operators typically
// rely on file or TCP output and keep the console at "warn" or higher.
type ConsoleOutputConfig struct {
	// Enabled controls whether findings are written to stdout.
	Enabled bool `yaml:"enabled"`

	// Format selects the output encoding: "json" (structured, machine-readable)
	// or "text" (human-readable with lipgloss styling when a TTY is detected).
	Format string `yaml:"format"` // "json" or "text"

	// Level is the minimum severity that will be printed. Findings below this
	// threshold are silently dropped for this sink. Valid values match the
	// finding.Severity constants: "critical", "high", "medium", "info".
	Level string `yaml:"level"`
}

// FileOutputConfig configures file output with built-in log rotation. The
// rotation parameters (MaxSizeMB, MaxAgeDays, MaxBackups) keep disk usage
// bounded without requiring external logrotate configuration.
type FileOutputConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`   // absolute path to the log file
	Format  string `yaml:"format"` // "json" or "text"
	Level   string `yaml:"level"`  // minimum severity to log

	// MaxSizeMB is the maximum size in megabytes before the log is rotated.
	MaxSizeMB int `yaml:"max_size_mb"`

	// MaxAgeDays is the maximum number of days to retain old log files.
	MaxAgeDays int `yaml:"max_age_days"`

	// MaxBackups is the maximum number of rotated log files to keep.
	MaxBackups int `yaml:"max_backups"`
}

// TCPOutputConfig configures TCP output, typically used to ship JSON findings
// to a log aggregator like Fluent Bit, Logstash, or Vector. The connection
// uses exponential backoff between RetryInterval and MaxRetryInterval when the
// remote endpoint is unreachable.
type TCPOutputConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"` // host:port of the TCP listener
	Format  string `yaml:"format"`  // "json" (only JSON is meaningful over TCP)
	Level   string `yaml:"level"`   // minimum severity to forward

	// RetryInterval is the initial delay between reconnection attempts when the
	// TCP sink is unreachable. Doubles on each failure up to MaxRetryInterval.
	RetryInterval time.Duration `yaml:"retry_interval"`

	// MaxRetryInterval caps the exponential backoff to prevent excessively long
	// gaps between connection attempts.
	MaxRetryInterval time.Duration `yaml:"max_retry_interval"`
}

// WebhookOutputConfig configures webhook output for high-severity alerting
// (e.g. posting to Slack, PagerDuty, or a custom endpoint). The Cooldown
// field prevents alert storms by suppressing duplicate webhook calls within
// the cooldown window.
type WebhookOutputConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`   // full URL to POST findings to
	Level   string `yaml:"level"` // minimum severity — typically "high" or "critical"

	// Cooldown is the minimum time between webhook calls for the same finding.
	// This prevents flooding an alerting channel when a module re-detects the
	// same issue on every scan cycle.
	Cooldown time.Duration `yaml:"cooldown"`

	// Template is an optional Go text/template string used to customize the
	// webhook body. When empty a default JSON payload is sent.
	Template string `yaml:"template"`
}

// DashboardConfig configures the agent-to-dashboard reporting channel. When
// both URL and Secret are set, the agent periodically publishes its status
// and findings to the central Trapline dashboard for fleet-wide visibility.
type DashboardConfig struct {
	// URL is the dashboard server endpoint (e.g. "https://monitor.example.com/trapline").
	URL string `yaml:"url"`

	// Secret is the per-host publish secret used to authenticate reports.
	Secret string `yaml:"secret"`
}

// UpdateConfig configures the self-update mechanism. Trapline polls a GitHub
// repository's releases API on a configurable interval and can automatically
// download, verify, and replace its own binary. See the updater package for
// the implementation.
type UpdateConfig struct {
	// Enabled controls whether the auto-update loop runs at all.
	Enabled bool `yaml:"enabled"`

	// Repo is the GitHub "owner/repo" slug to check for releases
	// (e.g. "jclement/tripline").
	Repo string `yaml:"repo"`

	// Channel selects the release channel. Currently only "stable" is used;
	// future channels (e.g. "beta") may filter by pre-release tags.
	Channel string `yaml:"channel"`

	// CheckInterval is how often the updater polls GitHub for a new release.
	CheckInterval time.Duration `yaml:"check_interval"`

	// AutoApply controls whether a discovered update is downloaded and installed
	// automatically. When false the update is reported but not applied.
	AutoApply bool `yaml:"auto_apply"`
}

// DefaultsConfig holds default module settings that are inherited by any
// module that does not explicitly override these values. This keeps the YAML
// concise: operators set defaults once, then only list exceptions per-module.
type DefaultsConfig struct {
	// Interval is the default time between successive scans for a module.
	Interval time.Duration `yaml:"interval"`

	// Severity is the default severity label attached to findings when a module
	// does not specify its own.
	Severity string `yaml:"severity"`

	// Cooldown is the default minimum interval between re-alerting on the same
	// finding. Prevents duplicate alerts for persistent issues.
	Cooldown time.Duration `yaml:"cooldown"`
}

// ModuleConfig holds per-module configuration. Each entry in [Config.Modules]
// maps a module name to one of these structs. Fields left at their zero value
// inherit from [Config.Defaults] during validation.
type ModuleConfig struct {
	// Enabled controls whether the module's scanner goroutine is started.
	Enabled bool `yaml:"enabled"`

	// Interval overrides [DefaultsConfig.Interval] for this specific module.
	// A zero value means "use the global default".
	Interval time.Duration `yaml:"interval"`

	// Extra holds module-specific configuration as raw YAML key-value pairs.
	// The ",inline" tag causes any YAML keys not matching Enabled or Interval
	// to be captured here. This allows each module to define its own schema
	// (e.g. file paths, process names, thresholds) without changing this
	// package. Modules retrieve their settings by type-asserting values from
	// this map.
	Extra map[string]interface{} `yaml:",inline"`
}

// Default returns a Config populated with production-ready defaults. These
// values are chosen so that a freshly installed Trapline monitors all major
// subsystems out of the box with reasonable intervals:
//
//   - StateDir: /var/lib/trapline — the FHS-compliant location for variable
//     application data. Owned by root with mode 0700.
//
//   - Console output: enabled at "warn" level in JSON format. In daemon mode
//     stdout is rarely observed, so only warnings and above are printed. JSON
//     is the default because stdout is more likely piped to journald than read
//     by a human.
//
//   - File output: enabled at "info" level to /var/log/trapline/trapline.log.
//     50 MB rotation with 30-day retention and 5 backups balances disk use
//     against forensic value.
//
//   - TCP output: disabled by default. The address 127.0.0.1:51888 is the
//     conventional local Fluent Bit input. Retry starts at 5 s and caps at
//     60 s to avoid hammering a down collector.
//
//   - Webhook output: disabled by default. When enabled, "high" severity
//     threshold and 1-hour cooldown prevent alert fatigue.
//
//   - Update: enabled, checking every 6 hours from the project's GitHub repo
//     with auto-apply on. Keeps the fleet current without operator intervention.
//
//   - Defaults: 5-minute scan interval, "medium" severity, 1-hour cooldown.
//     These are sensible middle-ground values for most modules.
//
//   - Modules: all 13 built-in modules are enabled with intervals tuned to
//     their cost and volatility:
//   - file-integrity: 5 m — hashing is moderately expensive
//   - packages: 1 h — package lists rarely change
//   - ports: 60 s — new listeners appear quickly
//   - processes: 30 s — most time-sensitive for intrusion detection
//   - containers: 60 s — Docker state changes frequently
//   - users: 15 m — user/group changes are infrequent
//   - cron: 15 m — crontab edits are rare
//   - suid: 1 h — SUID binaries rarely change
//   - ssh: 15 m — authorized_keys and sshd config changes are notable
//   - permissions: 1 h — permission audits are expensive
//   - rootkit: 30 m — thorough checks are CPU-intensive
//   - malware: 15 m — balances detection speed with CPU cost
//   - network: 60 s — routing/DNS changes matter quickly
func Default() *Config {
	return &Config{
		StateDir: "/var/lib/trapline",
		Output: OutputConfig{
			Console: ConsoleOutputConfig{
				Enabled: true,
				Format:  "json",
				Level:   "warn",
			},
			File: FileOutputConfig{
				Enabled:    true,
				Path:       "/var/log/trapline/trapline.log",
				Format:     "json",
				Level:      "info",
				MaxSizeMB:  50,
				MaxAgeDays: 30,
				MaxBackups: 5,
			},
			TCP: TCPOutputConfig{
				Enabled:          false,
				Address:          "127.0.0.1:51888",
				Format:           "json",
				Level:            "info",
				RetryInterval:    5 * time.Second,
				MaxRetryInterval: 60 * time.Second,
			},
			Webhook: WebhookOutputConfig{
				Enabled:  false,
				Level:    "high",
				Cooldown: time.Hour,
			},
		},
		Update: UpdateConfig{
			Enabled:       true,
			Repo:          "jclement/tripline",
			Channel:       "stable",
			CheckInterval: 6 * time.Hour,
			AutoApply:     true,
		},
		Defaults: DefaultsConfig{
			Interval: 5 * time.Minute,
			Severity: "medium",
			Cooldown: time.Hour,
		},
		Modules: map[string]ModuleConfig{
			"file-integrity": {Enabled: true, Interval: 5 * time.Minute},
			"packages":       {Enabled: true, Interval: time.Hour},
			"ports":          {Enabled: true, Interval: 60 * time.Second},
			"processes":      {Enabled: true, Interval: 30 * time.Second},
			"containers":     {Enabled: true, Interval: 60 * time.Second},
			"users":          {Enabled: true, Interval: 15 * time.Minute},
			"cron":           {Enabled: true, Interval: 15 * time.Minute},
			"suid":           {Enabled: true, Interval: time.Hour},
			"ssh":            {Enabled: true, Interval: 15 * time.Minute},
			"permissions":    {Enabled: true, Interval: time.Hour},
			"rootkit":        {Enabled: true, Interval: 30 * time.Minute},
			"malware":        {Enabled: true, Interval: 15 * time.Minute},
			"network":        {Enabled: true, Interval: 60 * time.Second},
		},
	}
}

// Load reads and parses a YAML config file, merging user overrides on top of
// the built-in defaults. The merge strategy relies on gopkg.in/yaml.v3's
// behavior of unmarshaling into an already-populated struct: any YAML key
// present in the file overwrites the corresponding field; keys absent from the
// file leave the default value intact. After merging, [Validate] is called to
// enforce invariants and fill in any remaining gaps (e.g. modules with a zero
// interval inherit the global default).
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Validate checks the config for internal consistency and fills in missing
// per-module values from the global defaults. Specifically:
//
//   - StateDir must be non-empty; it is the root for all persistent data and
//     without it no baseline can be stored.
//
//   - Any enabled module whose Interval is zero inherits [Defaults.Interval].
//     This allows modules defined in YAML as just "enabled: true" to
//     automatically pick up the global scan cadence.
//
// Validate is called automatically by [Load] but can also be called manually
// after programmatic configuration changes.
func (c *Config) Validate() error {
	if c.StateDir == "" {
		return fmt.Errorf("state_dir is required")
	}
	for name, mod := range c.Modules {
		if mod.Enabled && mod.Interval == 0 {
			// Apply the global default interval to modules that did not specify
			// their own. The map value is a copy (ModuleConfig is a value type),
			// so we must write it back.
			mod.Interval = c.Defaults.Interval
			c.Modules[name] = mod
		}
	}
	return nil
}

// ModuleInterval returns the effective scan interval for the named module. If
// the module has an explicit interval configured, that value is returned;
// otherwise the global [Defaults.Interval] is used. This is the single source
// of truth for "how often should this module run?" used by the scheduler.
func (c *Config) ModuleInterval(name string) time.Duration {
	if mod, ok := c.Modules[name]; ok && mod.Interval > 0 {
		return mod.Interval
	}
	return c.Defaults.Interval
}

// ModuleEnabled returns whether the named module is enabled in the config.
// Modules not present in the Modules map at all are considered disabled; only
// an explicit "enabled: true" entry activates a module.
func (c *Config) ModuleEnabled(name string) bool {
	if mod, ok := c.Modules[name]; ok {
		return mod.Enabled
	}
	return false
}

// DefaultConfigYAML returns the default configuration serialized as YAML bytes.
// This is used by "trapline install" to write an initial config file to disk
// when no config exists yet, giving the operator a fully commented starting
// point that they can customize.
func DefaultConfigYAML() ([]byte, error) {
	return yaml.Marshal(Default())
}
