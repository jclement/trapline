package suid

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jclement/trapline/internal/engine"
)

func testModuleConfig(t *testing.T) engine.ModuleConfig {
	t.Helper()
	dir := t.TempDir()
	return engine.ModuleConfig{
		StateDir:     dir,
		BaselinesDir: filepath.Join(dir, "baselines"),
		Settings:     make(map[string]interface{}),
	}
}

func TestName(t *testing.T) {
	if New().Name() != "suid" {
		t.Error("wrong name")
	}
}

func TestScanEmptyDir(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	m := New()
	m.scanPaths = []string{dir}
	m.excludePaths = nil
	_ = m.Init(cfg)

	findings, err := m.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty dir, got %d", len(findings))
	}
}

func TestDetectsNewSuid(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	m := New()
	m.scanPaths = []string{dir}
	m.excludePaths = nil
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background()) // baseline (empty)

	// Create a SUID binary
	suidFile := filepath.Join(dir, "escalate")
	_ = os.WriteFile(suidFile, []byte("#!/bin/sh\n"), 0755)
	if err := os.Chmod(suidFile, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "suid-unexpected:"+suidFile {
			found = true
		}
	}
	if !found {
		t.Error("expected suid-unexpected finding")
	}
}

func TestDetectsRemovedSuid(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	suidFile := filepath.Join(dir, "legit")
	_ = os.WriteFile(suidFile, []byte("#!/bin/sh\n"), 0755)
	if err := os.Chmod(suidFile, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.scanPaths = []string{dir}
	m.excludePaths = nil
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background()) // baseline

	_ = os.Remove(suidFile)

	findings, _ := m.Scan(context.Background())
	found := false
	for _, f := range findings {
		if f.FindingID == "suid-removed:"+suidFile {
			found = true
		}
	}
	if !found {
		t.Error("expected suid-removed finding")
	}
}

func TestExcludePaths(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()
	excludeDir := filepath.Join(dir, "docker")
	if err := os.MkdirAll(excludeDir, 0755); err != nil {
		t.Fatal(err)
	}

	suidFile := filepath.Join(excludeDir, "ignore-me")
	_ = os.WriteFile(suidFile, []byte("#!/bin/sh\n"), 0755)
	if err := os.Chmod(suidFile, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	m := New()
	m.scanPaths = []string{dir}
	m.excludePaths = []string{excludeDir}
	_ = m.Init(cfg)

	// Even in baseline capture, excluded files shouldn't be tracked
	_, _ = m.Scan(context.Background())
	if _, ok := m.baseline.Entries[suidFile]; ok {
		t.Error("excluded SUID binary should not be in baseline")
	}
}

func TestRebaseline(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	m := New()
	m.scanPaths = []string{dir}
	m.excludePaths = nil
	_ = m.Init(cfg)
	_, _ = m.Scan(context.Background())

	suidFile := filepath.Join(dir, "new-legit")
	_ = os.WriteFile(suidFile, []byte("x"), 0755)
	if err := os.Chmod(suidFile, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}

	if err := m.Rebaseline(context.Background()); err != nil {
		t.Fatal(err)
	}
	findings, _ := m.Scan(context.Background())
	if len(findings) != 0 {
		t.Errorf("expected 0 findings after rebaseline, got %d", len(findings))
	}
}

func TestCancellation(t *testing.T) {
	cfg := testModuleConfig(t)
	dir := t.TempDir()

	m := New()
	m.scanPaths = []string{dir}
	m.excludePaths = nil
	_ = m.Init(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Should not hang
	_, _ = m.Scan(ctx)
}
