package packages

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type Module struct {
	store        *baseline.Store
	excludePaths []string
	// For testing
	VerifyCmd func(ctx context.Context) ([]byte, error)
}

func New() *Module {
	return &Module{
		excludePaths: []string{"/etc/"},
	}
}

func (m *Module) Name() string { return "packages" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store

	if paths, ok := cfg.Settings["exclude_paths"]; ok {
		if ps, ok := paths.([]interface{}); ok {
			for _, p := range ps {
				if s, ok := p.(string); ok {
					m.excludePaths = append(m.excludePaths, s)
				}
			}
		}
	}

	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	output, err := m.runVerify(ctx)
	if err != nil {
		return nil, nil // dpkg might not be available
	}

	var findings []finding.Finding
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 12 {
			continue
		}

		// dpkg --verify output format: "??5??????   /path/to/file"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		path := parts[len(parts)-1]

		// Check exclusions
		excluded := false
		for _, excl := range m.excludePaths {
			if strings.HasPrefix(path, excl) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}

		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "package-file-modified:" + path,
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("package file modified outside package manager: %s", path),
			Detail: map[string]interface{}{
				"path":   path,
				"status": parts[0],
			},
		})
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	// Packages module doesn't use baselines — it compares against dpkg's own database
	return nil
}

func (m *Module) runVerify(ctx context.Context) ([]byte, error) {
	if m.VerifyCmd != nil {
		return m.VerifyCmd(ctx)
	}
	cmd := exec.CommandContext(ctx, "dpkg", "--verify")
	output, err := cmd.Output()
	if err != nil {
		// dpkg --verify returns non-zero if there are modifications
		if exitErr, ok := err.(*exec.ExitError); ok {
			return append(output, exitErr.Stderr...), nil
		}
		return nil, err
	}
	return output, nil
}
