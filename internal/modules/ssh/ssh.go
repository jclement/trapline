package ssh

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type SSHBaseline struct {
	ConfigHash string            `json:"config_hash"`
	Settings   map[string]string `json:"settings"`
}

type Module struct {
	store          *baseline.Store
	baseline       SSHBaseline
	baselineLoaded bool
	ConfigPath     string
}

func New() *Module {
	return &Module{
		ConfigPath: "/etc/ssh/sshd_config",
	}
}

func (m *Module) Name() string { return "ssh" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)
	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.snapshot()
	if err != nil {
		return nil, nil // config may not exist
	}

	var findings []finding.Finding

	// Always check security settings regardless of baseline
	findings = append(findings, checkSecuritySettings(current.Settings)...)

	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		m.store.Save(m.Name(), m.baseline)
		return findings, nil
	}

	if current.ConfigHash != m.baseline.ConfigHash {
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "ssh-config-changed",
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   "sshd_config has been modified",
			Detail: map[string]interface{}{
				"baseline_hash": m.baseline.ConfigHash,
				"current_hash":  current.ConfigHash,
			},
		})
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.snapshot()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

func (m *Module) snapshot() (SSHBaseline, error) {
	data, err := os.ReadFile(m.ConfigPath)
	if err != nil {
		return SSHBaseline{}, err
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	settings := parseSSHConfig(string(data))

	return SSHBaseline{
		ConfigHash: hash,
		Settings:   settings,
	}, nil
}

func parseSSHConfig(content string) map[string]string {
	settings := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			settings[strings.ToLower(parts[0])] = parts[1]
		}
	}
	return settings
}

func checkSecuritySettings(settings map[string]string) []finding.Finding {
	var findings []finding.Finding

	checks := []struct {
		key     string
		badVals []string
		summary string
	}{
		{"passwordauthentication", []string{"yes"}, "PasswordAuthentication is enabled — should be 'no'"},
		{"permitrootlogin", []string{"yes"}, "PermitRootLogin is 'yes' — should be 'no' or 'prohibit-password'"},
		{"permitemptypasswords", []string{"yes"}, "PermitEmptyPasswords is enabled — should be 'no'"},
	}

	for _, check := range checks {
		if val, ok := settings[check.key]; ok {
			for _, bad := range check.badVals {
				if strings.EqualFold(val, bad) {
					findings = append(findings, finding.Finding{
						Timestamp: time.Now().UTC(),
						FindingID: "ssh-insecure-setting:" + check.key,
						Severity:  finding.SeverityHigh,
						Status:    finding.StatusNew,
						Summary:   check.summary,
						Detail: map[string]interface{}{
							"setting": check.key,
							"value":   val,
						},
					})
				}
			}
		}
	}

	return findings
}
