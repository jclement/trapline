package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level trapline configuration.
type Config struct {
	Hostname string          `yaml:"hostname"`
	StateDir string          `yaml:"state_dir"`
	Output   OutputConfig    `yaml:"output"`
	Update   UpdateConfig    `yaml:"update"`
	Defaults DefaultsConfig  `yaml:"defaults"`
	Modules  map[string]ModuleConfig `yaml:"modules"`
}

// OutputConfig configures all output sinks.
type OutputConfig struct {
	Console ConsoleOutputConfig `yaml:"console"`
	File    FileOutputConfig    `yaml:"file"`
	TCP     TCPOutputConfig     `yaml:"tcp"`
	Webhook WebhookOutputConfig `yaml:"webhook"`
}

// ConsoleOutputConfig configures stdout output.
type ConsoleOutputConfig struct {
	Enabled bool   `yaml:"enabled"`
	Format  string `yaml:"format"` // "json" or "text"
	Level   string `yaml:"level"`
}

// FileOutputConfig configures file output.
type FileOutputConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Path       string `yaml:"path"`
	Format     string `yaml:"format"`
	Level      string `yaml:"level"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxAgeDays int    `yaml:"max_age_days"`
	MaxBackups int    `yaml:"max_backups"`
}

// TCPOutputConfig configures TCP output.
type TCPOutputConfig struct {
	Enabled          bool          `yaml:"enabled"`
	Address          string        `yaml:"address"`
	Format           string        `yaml:"format"`
	Level            string        `yaml:"level"`
	RetryInterval    time.Duration `yaml:"retry_interval"`
	MaxRetryInterval time.Duration `yaml:"max_retry_interval"`
}

// WebhookOutputConfig configures webhook output.
type WebhookOutputConfig struct {
	Enabled  bool          `yaml:"enabled"`
	URL      string        `yaml:"url"`
	Level    string        `yaml:"level"`
	Cooldown time.Duration `yaml:"cooldown"`
	Template string        `yaml:"template"`
}

// UpdateConfig configures self-update behavior.
type UpdateConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Repo          string        `yaml:"repo"`
	Channel       string        `yaml:"channel"`
	CheckInterval time.Duration `yaml:"check_interval"`
	AutoApply     bool          `yaml:"auto_apply"`
}

// DefaultsConfig holds default module settings.
type DefaultsConfig struct {
	Interval time.Duration `yaml:"interval"`
	Severity string        `yaml:"severity"`
	Cooldown time.Duration `yaml:"cooldown"`
}

// ModuleConfig holds per-module configuration.
type ModuleConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	// Extra holds module-specific configuration as raw YAML.
	Extra map[string]interface{} `yaml:",inline"`
}

// Default returns a Config with sane defaults.
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

// Load reads and parses a config file, merging with defaults.
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

// Validate checks the config for errors.
func (c *Config) Validate() error {
	if c.StateDir == "" {
		return fmt.Errorf("state_dir is required")
	}
	for name, mod := range c.Modules {
		if mod.Enabled && mod.Interval == 0 {
			// Apply default interval
			mod.Interval = c.Defaults.Interval
			c.Modules[name] = mod
		}
	}
	return nil
}

// ModuleInterval returns the effective interval for a module.
func (c *Config) ModuleInterval(name string) time.Duration {
	if mod, ok := c.Modules[name]; ok && mod.Interval > 0 {
		return mod.Interval
	}
	return c.Defaults.Interval
}

// ModuleEnabled returns whether a module is enabled.
func (c *Config) ModuleEnabled(name string) bool {
	if mod, ok := c.Modules[name]; ok {
		return mod.Enabled
	}
	return false
}

// DefaultConfig returns the default config as YAML bytes (for `trapline install`).
func DefaultConfigYAML() ([]byte, error) {
	return yaml.Marshal(Default())
}
