package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jclement/tripline/internal/config"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/internal/install"
	"github.com/jclement/tripline/internal/server"
	"github.com/jclement/tripline/internal/modules/containers"
	"github.com/jclement/tripline/internal/modules/cron"
	"github.com/jclement/tripline/internal/modules/fileintegrity"
	"github.com/jclement/tripline/internal/modules/malware"
	"github.com/jclement/tripline/internal/modules/network"
	"github.com/jclement/tripline/internal/modules/packages"
	"github.com/jclement/tripline/internal/modules/permissions"
	"github.com/jclement/tripline/internal/modules/ports"
	"github.com/jclement/tripline/internal/modules/processes"
	"github.com/jclement/tripline/internal/modules/rootkit"
	"github.com/jclement/tripline/internal/modules/ssh"
	"github.com/jclement/tripline/internal/modules/suid"
	"github.com/jclement/tripline/internal/modules/users"
	"github.com/jclement/tripline/internal/output"
	"github.com/jclement/tripline/internal/store"
	"github.com/jclement/tripline/internal/taglines"
	"github.com/jclement/tripline/internal/tui"
	"github.com/jclement/tripline/internal/updater"
	"github.com/jclement/tripline/pkg/finding"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"

	// errFindingsPresent is returned when a scan completes with findings.
	// main() treats this as exit code 1 without printing an error message.
	errFindingsPresent = errors.New("findings present")
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	configPath := install.ConfigPath
	quiet := false
	args := os.Args[1:]
	cmd := ""
	var extraArgs []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "--quiet", "-q":
			quiet = true
		case "--verbose", "-v":
			// reserved
		default:
			if cmd == "" && !strings.HasPrefix(args[i], "-") {
				cmd = args[i]
			} else {
				extraArgs = append(extraArgs, args[i])
			}
		}
	}

	_ = quiet

	var err error
	switch cmd {
	case "run":
		err = cmdRun(configPath)
	case "scan":
		err = cmdScan(configPath, extraArgs)
	case "status":
		err = cmdStatus(configPath)
	case "install":
		err = cmdInstall(extraArgs)
	case "uninstall":
		err = cmdUninstall(extraArgs)
	case "doctor":
		err = cmdDoctor(configPath)
	case "rebaseline":
		err = cmdRebaseline(configPath, extraArgs)
	case "findings":
		err = cmdFindings(configPath, extraArgs)
	case "ignore":
		err = cmdIgnore(configPath, extraArgs)
	case "update":
		err = cmdUpdate(configPath, extraArgs)
	case "config":
		err = cmdConfig(configPath, extraArgs)
	case "bench":
		err = cmdBench(configPath)
	case "server":
		err = cmdServer(extraArgs)
	case "version":
		err = cmdVersion(extraArgs)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, errFindingsPresent) {
			os.Exit(1)
		}
		if tui.IsTTY() {
			fmt.Fprintln(os.Stderr, tui.Error.Render("Error: "+err.Error()))
		} else {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}

func printUsage() {
	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Println(tui.FormatSection("Lifecycle"))
		fmt.Println("  install              Install binary, config, systemd unit, start service")
		fmt.Println("  uninstall            Stop service, remove everything")
		fmt.Println("  update               Check for and apply updates from GitHub")
		fmt.Println("  doctor               Validate installation health")
		fmt.Println()
		fmt.Println(tui.FormatSection("Operations"))
		fmt.Println("  run                  Start daemon (foreground, for systemd)")
		fmt.Println("  server               Start dashboard server (accepts remote findings)")
		fmt.Println("  status               Show module status and active findings")
		fmt.Println("  scan                 Run all modules once, print results, exit")
		fmt.Println("  scan -f              Follow mode: continuous colored live log")
		fmt.Println("  bench                Run benchmark passes and show per-module timing")
		fmt.Println("  rebaseline           Capture current state as known-good")
		fmt.Println("  findings             List active findings")
		fmt.Println()
		fmt.Println(tui.FormatSection("Finding Management"))
		fmt.Println("  ignore <hash>        Ignore a finding by its hash ID")
		fmt.Println("  ignore list          List all ignored findings")
		fmt.Println("  ignore remove <hash> Stop ignoring a finding")
		fmt.Println()
		fmt.Println(tui.FormatSection("Configuration"))
		fmt.Println("  config check         Validate configuration")
		fmt.Println("  config show          Dump effective config")
		fmt.Println()
		fmt.Println(tui.FormatSection("Info"))
		fmt.Println("  version              Print version info")
		fmt.Println("  help                 Show this help")
		fmt.Println()
		fmt.Println(tui.Dimmed.Render("Global flags: --config PATH  --quiet  --verbose"))
	} else {
		fmt.Println(`Trapline — host integrity and security monitoring daemon

Usage: trapline <command> [options]

Lifecycle:
  install              Install binary, config, systemd unit, start service
  uninstall            Stop service, remove everything
  update               Check for and apply updates from GitHub
  doctor               Validate installation health

Operations:
  run                  Start daemon (foreground, for systemd)
  server               Start dashboard server (accepts remote findings)
  status               Show module status and active findings
  scan                 Run all modules once, print results, exit
  scan -f              Follow mode: continuous colored live log
  bench                Run benchmark passes and show per-module timing
  rebaseline           Capture current state as known-good
  findings             List active findings

Finding Management:
  ignore <hash>        Ignore a finding by its hash ID
  ignore list          List all ignored findings
  ignore remove <hash> Stop ignoring a finding

Configuration:
  config check         Validate configuration
  config show          Dump effective config

Info:
  version              Print version info
  help                 Show this help

Global flags:
  --config PATH        Config file path (default: /etc/trapline/trapline.yml)
  --quiet              Suppress non-essential output
  --verbose            Enable debug output`)
	}
}

func loadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}

func openStore(cfg *config.Config) (*store.Store, error) {
	return store.Open(cfg.StateDir)
}

func buildEngine(cfg *config.Config, handler engine.FindingHandler) *engine.Engine {
	e := engine.New(cfg, handler, version)
	e.Register(fileintegrity.New())
	e.Register(packages.New())
	e.Register(ports.New())
	e.Register(processes.New())
	e.Register(users.New())
	e.Register(containers.New())
	e.Register(cron.New())
	e.Register(suid.New())
	e.Register(ssh.New())
	e.Register(permissions.New())
	e.Register(rootkit.New())
	e.Register(malware.New())
	e.Register(network.New())
	return e
}

// --- Commands ---

func cmdRun(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	db, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer db.Close()

	// Prune stale ignores on startup (60 days)
	if pruned, _ := db.PruneStaleIgnores(60 * 24 * time.Hour); pruned > 0 {
		fmt.Printf("Pruned %d stale ignore(s)\n", pruned)
	}

	mgr, err := output.NewManager(cfg.Output)
	if err != nil {
		return fmt.Errorf("setting up outputs: %w", err)
	}
	defer mgr.Close()

	// Add dashboard sink if configured
	mgr.AddDashboardSink(cfg.Dashboard.URL, cfg.Dashboard.Secret)

	handler := func(f *finding.Finding) {
		hash, ignored, _ := db.RecordFinding(f)
		if ignored {
			return
		}
		f.ScanID = hash // stash the hash in ScanID for display
		mgr.Emit(f)
	}

	eng := buildEngine(cfg, handler)
	if err := eng.Init(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				fmt.Println("Shutting down...")
				cancel()
				return
			case syscall.SIGHUP:
				fmt.Println("Reloading configuration...")
			}
		}
	}()

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Printf("Starting daemon with %d modules enabled\n\n", len(eng.EnabledModules()))
	} else {
		fmt.Printf("Trapline %s starting (%d modules enabled)\n", version, len(eng.EnabledModules()))
	}

	eng.Run(ctx)
	return nil
}

func cmdScan(configPath string, args []string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	db, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer db.Close()

	var moduleName string
	follow := false
	for i, arg := range args {
		if arg == "--module" && i+1 < len(args) {
			moduleName = args[i+1]
		}
		if arg == "-f" || arg == "--follow" {
			follow = true
		}
	}

	// Follow mode: run as a lightweight daemon with console-only output.
	// Each new finding appears as a colored log line. Ctrl-C to stop.
	if follow {
		return cmdScanFollow(cfg, db)
	}

	eng := buildEngine(cfg, nil)
	if err := eng.Init(); err != nil {
		return err
	}

	ctx := context.Background()

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		if moduleName != "" {
			fmt.Printf("Scanning module: %s\n\n", tui.Subtitle.Render(moduleName))
		} else {
			fmt.Printf("Scanning %d modules (packages module may take 30s)...\n\n", len(eng.EnabledModules()))
		}
	}

	var findings []finding.Finding
	if moduleName != "" {
		findings, err = eng.ScanModule(ctx, moduleName)
	} else {
		findings, err = eng.ScanAll(ctx)
	}
	if err != nil {
		return err
	}

	// Filter ignored findings and record in store
	var active []finding.Finding
	for i := range findings {
		f := &findings[i]
		hash, ignored, _ := db.RecordFinding(f)
		if !ignored {
			f.ScanID = hash
			active = append(active, *f)
		}
	}

	if len(active) == 0 {
		if tui.IsTTY() {
			fmt.Println(tui.Success.Render("No findings. System looks clean."))
		} else {
			fmt.Println("No findings.")
		}
		return nil
	}

	if tui.IsTTY() {
		for _, f := range active {
			fmt.Println(tui.FormatFinding(&f))
		}
		fmt.Printf("\n%s\n", tui.Warning.Render(fmt.Sprintf("%d finding(s). Use 'trapline ignore <hash>' to suppress.", len(active))))
	} else {
		for _, f := range active {
			fmt.Printf("[%s] %s %s: %s\n", strings.ToUpper(string(f.Severity)), f.ScanID, f.FindingID, f.Summary)
		}
		fmt.Printf("\n%d finding(s)\n", len(active))
	}

	return errFindingsPresent
}

// cmdScanFollow runs continuous scanning with live colored output.
// Like `tail -f` for security findings. Each new finding appears once
// as a colored log line. Ctrl-C to stop.
func cmdScanFollow(cfg *config.Config, db *store.Store) error {
	// Force console output to text mode at info level
	cfg.Output.Console.Enabled = true
	cfg.Output.Console.Format = "text"
	cfg.Output.Console.Level = "info"
	// Disable other sinks — this is interactive
	cfg.Output.File.Enabled = false
	cfg.Output.TCP.Enabled = false
	cfg.Output.Webhook.Enabled = false

	mgr, err := output.NewManager(cfg.Output)
	if err != nil {
		return err
	}
	defer mgr.Close()

	handler := func(f *finding.Finding) {
		hash, ignored, _ := db.RecordFinding(f)
		if ignored {
			return
		}
		f.ScanID = hash
		mgr.Emit(f)
	}

	eng := buildEngine(cfg, handler)
	if err := eng.Init(); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Printf("Watching %d modules... %s\n\n",
			len(eng.EnabledModules()),
			tui.Dimmed.Render("(Ctrl-C to stop)"))
	} else {
		fmt.Printf("Trapline %s — continuous scan (%d modules)\n", version, len(eng.EnabledModules()))
	}

	eng.Run(ctx)
	return nil
}

func cmdStatus(configPath string) error {
	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
	} else {
		fmt.Printf("Trapline %s\n\n", version)
	}

	cfg, cfgErr := loadConfig(configPath)

	type modInfo struct {
		name     string
		enabled  bool
		interval string
		detail   string
	}

	moduleNames := []string{
		"file-integrity", "packages", "ports", "processes",
		"containers", "users", "cron", "suid", "ssh", "permissions",
		"rootkit", "malware", "network",
	}

	if tui.IsTTY() {
		fmt.Println(tui.FormatSection("Modules"))
		fmt.Println()
		for _, name := range moduleNames {
			enabled := false
			interval := "-"
			detail := ""
			if cfgErr == nil {
				enabled = cfg.ModuleEnabled(name)
				if enabled {
					interval = cfg.ModuleInterval(name).String()
				}
			}
			// Autodetection notes
			switch name {
			case "malware":
				if _, err := exec.LookPath("clamdscan"); err == nil {
					detail = "clamdscan available"
				} else if _, err := exec.LookPath("clamscan"); err == nil {
					detail = "clamscan available"
				} else {
					detail = "ClamAV not installed"
				}
			case "containers":
				if _, err := os.Stat("/var/run/docker.sock"); err == nil {
					detail = "Docker socket found"
				} else {
					detail = "no Docker socket"
				}
			case "packages":
				if _, err := exec.LookPath("dpkg"); err == nil {
					detail = "dpkg available"
				} else {
					detail = "dpkg not found"
				}
			}
			fmt.Println(tui.FormatModuleStatus(name, enabled, interval, detail))
		}

		// Show ignore count
		if cfgErr == nil {
			if db, err := openStore(cfg); err == nil {
				if ignores, err := db.ListIgnores(); err == nil && len(ignores) > 0 {
					fmt.Printf("\n%s\n", tui.Dimmed.Render(fmt.Sprintf("  %d finding(s) currently ignored", len(ignores))))
				}
				db.Close()
			}
		}
	} else {
		for _, name := range moduleNames {
			status := "disabled"
			interval := "-"
			if cfgErr == nil && cfg.ModuleEnabled(name) {
				status = "enabled"
				interval = cfg.ModuleInterval(name).String()
			}
			fmt.Printf("%-20s %10s  %s\n", name, interval, status)
		}
	}

	fmt.Println()
	return nil
}

func cmdDoctor(configPath string) error {
	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Println(tui.Title.Render("Installation Health Check"))
		fmt.Println()
	}

	result := install.Doctor()

	if tui.IsTTY() {
		currentCategory := ""
		for _, c := range result.Checks {
			if c.Category != currentCategory {
				if currentCategory != "" {
					fmt.Println()
				}
				fmt.Println(tui.FormatSection(c.Category))
				currentCategory = c.Category
			}
			var mark string
			var style func(string) string
			switch c.Status {
			case install.CheckPassed:
				mark = tui.CheckMark(true)
				style = func(s string) string { return s }
			case install.CheckWarning:
				mark = tui.WarnMark()
				style = func(s string) string { return tui.Warning.Render(s) }
			case install.CheckError:
				mark = tui.CheckMark(false)
				style = func(s string) string { return tui.Error.Render(s) }
			}
			fmt.Printf("  %s %s\n", mark, style(c.Detail))
			if c.Fix != "" {
				fmt.Printf("    %s\n", tui.Dimmed.Render("Fix: "+c.Fix))
			}
		}

		// Module autodetection
		fmt.Println()
		fmt.Println(tui.FormatSection("Module Autodetection"))
		detections := []struct {
			name  string
			check func() (bool, string)
		}{
			{"ClamAV (malware)", func() (bool, string) {
				if p, err := exec.LookPath("clamdscan"); err == nil {
					return true, "clamdscan at " + p
				}
				if p, err := exec.LookPath("clamscan"); err == nil {
					return true, "clamscan at " + p
				}
				return false, "not installed -- malware module will skip scanning"
			}},
			{"Docker (containers)", func() (bool, string) {
				if _, err := os.Stat("/var/run/docker.sock"); err == nil {
					return true, "Docker socket at /var/run/docker.sock"
				}
				return false, "no Docker socket found"
			}},
			{"dpkg (packages)", func() (bool, string) {
				if p, err := exec.LookPath("dpkg"); err == nil {
					return true, "dpkg at " + p
				}
				return false, "not found -- packages module will skip"
			}},
			{"systemd", func() (bool, string) {
				if _, err := os.Stat("/run/systemd/system"); err == nil {
					return true, "systemd present"
				}
				return false, "systemd not found"
			}},
		}
		for _, d := range detections {
			found, detail := d.check()
			if found {
				fmt.Printf("  %s %s  %s\n", tui.CheckMark(true), d.name, tui.Dimmed.Render(detail))
			} else {
				fmt.Printf("  %s %s  %s\n", tui.Dimmed.Render("-"), d.name, tui.Dimmed.Render(detail))
			}
		}

		// Summary
		fmt.Println()
		summary := fmt.Sprintf("  %d passed, %d warnings, %d errors",
			result.Passed, result.Warnings, result.Errors)
		if result.Errors > 0 {
			fmt.Println(tui.Error.Render(summary))
		} else if result.Warnings > 0 {
			fmt.Println(tui.Warning.Render(summary))
		} else {
			fmt.Println(tui.Success.Render(summary))
		}
	} else {
		result.Print()
	}

	if result.Errors > 0 {
		os.Exit(1)
	}
	return nil
}

func cmdIgnore(configPath string, args []string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		// Use default state dir if config fails
		cfg = config.Default()
	}

	db, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer db.Close()

	if len(args) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  trapline ignore <hash>             Ignore a finding")
		fmt.Println("  trapline ignore <hash> -r 'reason' Ignore with a reason")
		fmt.Println("  trapline ignore list               List ignored findings")
		fmt.Println("  trapline ignore remove <hash>      Stop ignoring a finding")
		fmt.Println("  trapline ignore prune              Remove stale ignores (>60 days)")
		return nil
	}

	subcmd := args[0]

	switch subcmd {
	case "list":
		ignores, err := db.ListIgnores()
		if err != nil {
			return err
		}
		if len(ignores) == 0 {
			fmt.Println("No ignored findings.")
			return nil
		}
		if tui.IsTTY() {
			fmt.Println(tui.FormatBanner(version, taglines.Random()))
			fmt.Println(tui.FormatSection("Ignored Findings"))
			fmt.Println()
			for _, ig := range ignores {
				hash := tui.Subtitle.Render(ig.Hash)
				mod := tui.Dimmed.Render(ig.Module)
				reason := ""
				if ig.Reason != "" {
					reason = tui.Dimmed.Render(" -- " + ig.Reason)
				}
				hits := ""
				if ig.HitCount > 0 {
					hits = tui.Dimmed.Render(fmt.Sprintf(" (suppressed %dx)", ig.HitCount))
				}
				fmt.Printf("  %s  %s  %s%s%s\n", hash, mod, ig.Summary, reason, hits)
			}
		} else {
			for _, ig := range ignores {
				fmt.Printf("%s  %-16s  %s", ig.Hash, ig.Module, ig.Summary)
				if ig.Reason != "" {
					fmt.Printf("  reason=%s", ig.Reason)
				}
				fmt.Printf("  hits=%d\n", ig.HitCount)
			}
		}
		return nil

	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: trapline ignore remove <hash>")
		}
		hash := args[1]
		if err := db.UnignoreFinding(hash); err != nil {
			return err
		}
		fmt.Printf("Removed ignore for %s\n", hash)
		return nil

	case "prune":
		pruned, err := db.PruneStaleIgnores(60 * 24 * time.Hour)
		if err != nil {
			return err
		}
		fmt.Printf("Pruned %d stale ignore(s)\n", pruned)
		return nil

	default:
		// Treat as a hash to ignore
		hash := subcmd
		reason := ""
		for i, arg := range args[1:] {
			if (arg == "-r" || arg == "--reason") && i+1 < len(args[1:]) {
				reason = args[i+2]
			}
		}
		if err := db.IgnoreFinding(hash, reason); err != nil {
			return err
		}
		if tui.IsTTY() {
			fmt.Printf("%s Finding %s will be suppressed.\n", tui.CheckMark(true), tui.Subtitle.Render(hash))
			if reason != "" {
				fmt.Printf("  %s\n", tui.Dimmed.Render("Reason: "+reason))
			}
		} else {
			fmt.Printf("Ignored %s\n", hash)
		}
		return nil
	}
}

func cmdInstall(args []string) error {
	noStart := false
	for _, arg := range args {
		if arg == "--no-start" {
			noStart = true
		}
	}
	defaultCfg, err := config.DefaultConfigYAML()
	if err != nil {
		return err
	}
	return install.Install(version, defaultCfg, noStart)
}

func cmdUninstall(args []string) error {
	keepConfig := false
	confirmed := false
	for _, arg := range args {
		if arg == "--keep-config" {
			keepConfig = true
		}
		if arg == "--yes" || arg == "-y" {
			confirmed = true
		}
	}
	if !confirmed {
		fmt.Print("Remove trapline and all data? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(answer) != "y" {
			fmt.Println("Cancelled.")
			return nil
		}
	}
	return install.Uninstall(keepConfig)
}

func cmdRebaseline(configPath string, args []string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	eng := buildEngine(cfg, nil)
	if err := eng.Init(); err != nil {
		return err
	}

	ctx := context.Background()

	var modules []string
	dryRun := false
	for i, arg := range args {
		if arg == "--module" && i+1 < len(args) {
			modules = append(modules, args[i+1])
		}
		if arg == "--dry-run" {
			dryRun = true
		}
	}

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
	}

	if dryRun {
		findings, err := eng.ScanAll(ctx)
		if err != nil {
			return err
		}
		if len(findings) == 0 {
			fmt.Println("No differences from current baseline.")
		} else {
			fmt.Println("These findings would be accepted as known-good:")
			for _, f := range findings {
				if tui.IsTTY() {
					fmt.Println(tui.FormatFinding(&f))
				} else {
					fmt.Printf("[%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.FindingID, f.Summary)
				}
			}
			fmt.Printf("\n%d finding(s) would be accepted.\n", len(findings))
		}
		return nil
	}

	if len(modules) > 0 {
		for _, mod := range modules {
			if err := eng.RebaselineModule(ctx, mod); err != nil {
				return err
			}
			if tui.IsTTY() {
				fmt.Printf("  %s %s\n", tui.CheckMark(true), mod)
			} else {
				fmt.Printf("Rebaselined: %s\n", mod)
			}
		}
	} else {
		if err := eng.RebaselineAll(ctx); err != nil {
			return err
		}
		if tui.IsTTY() {
			fmt.Println(tui.Success.Render("All modules rebaselined."))
		} else {
			fmt.Println("All modules rebaselined.")
		}
	}
	return nil
}

func cmdFindings(configPath string, args []string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	db, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer db.Close()

	// Check for --stored flag (show from DB instead of live scan)
	useDB := false
	formatJSON := false
	for _, arg := range args {
		if arg == "--stored" || arg == "--db" {
			useDB = true
		}
		if arg == "--json" {
			formatJSON = true
		}
	}

	if tui.IsTTY() && !formatJSON {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
	}

	if useDB {
		entries, err := db.ListFindings()
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			fmt.Println("No active findings in store.")
			return nil
		}
		if formatJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(entries)
		}
		for _, e := range entries {
			if tui.IsTTY() {
				badge := tui.SeverityBadge(finding.ParseSeverity(e.Severity))
				fmt.Printf("  %s %s  %s  %s\n",
					tui.Subtitle.Render(e.Hash), badge, e.Summary,
					tui.Dimmed.Render(fmt.Sprintf("(%dx, last %s)", e.HitCount, e.LastSeen.Format("Jan 2 15:04"))))
			} else {
				fmt.Printf("%s  [%s]  %s  (%dx)\n", e.Hash, e.Severity, e.Summary, e.HitCount)
			}
		}
		return nil
	}

	// Live scan
	eng := buildEngine(cfg, nil)
	if err := eng.Init(); err != nil {
		return err
	}

	findings, err := eng.ScanAll(context.Background())
	if err != nil {
		return err
	}

	var active []finding.Finding
	for i := range findings {
		f := &findings[i]
		hash, ignored, _ := db.RecordFinding(f)
		if !ignored {
			f.ScanID = hash
			active = append(active, *f)
		}
	}

	if len(active) == 0 {
		if tui.IsTTY() {
			fmt.Println(tui.Success.Render("No active findings."))
		} else {
			fmt.Println("No active findings.")
		}
		return nil
	}

	if formatJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(active)
	}

	if tui.IsTTY() {
		for _, f := range active {
			fmt.Println(tui.FormatFinding(&f))
		}
	} else {
		for _, f := range active {
			fmt.Printf("%s  [%s]  %s: %s\n", f.ScanID, strings.ToUpper(string(f.Severity)), f.FindingID, f.Summary)
		}
	}

	return nil
}

func cmdUpdate(configPath string, args []string) error {
	checkOnly := false
	for _, arg := range args {
		if arg == "--check" {
			checkOnly = true
		}
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		cfg = config.Default()
	}

	u := updater.New(cfg.Update.Repo, version, install.BinaryPath)
	result, err := u.Check(context.Background())
	if err != nil {
		return fmt.Errorf("checking for updates: %w", err)
	}

	if !result.Available {
		if tui.IsTTY() {
			fmt.Printf("%s Trapline %s is up to date.\n", tui.CheckMark(true), version)
		} else {
			fmt.Printf("Trapline %s is up to date.\n", version)
		}
		return nil
	}

	fmt.Printf("Update available: %s -> %s\n", result.CurrentVersion, result.LatestVersion)

	if checkOnly {
		return nil
	}

	fmt.Println("Downloading update...")
	if err := u.Apply(context.Background(), result); err != nil {
		return err
	}

	fmt.Println("Update applied. Restart the service: systemctl restart trapline")
	return nil
}

func cmdConfig(configPath string, args []string) error {
	subcmd := ""
	for _, arg := range args {
		if arg == "check" || arg == "show" || arg == "init" {
			subcmd = arg
		}
	}

	switch subcmd {
	case "check":
		cfg, err := loadConfig(configPath)
		if err != nil {
			return fmt.Errorf("config error: %w", err)
		}
		if tui.IsTTY() {
			fmt.Printf("%s Configuration OK (%d modules configured)\n", tui.CheckMark(true), len(cfg.Modules))
		} else {
			fmt.Printf("Configuration OK (%d modules configured)\n", len(cfg.Modules))
		}
		return nil

	case "show":
		cfg, err := loadConfig(configPath)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(cfg)

	case "init":
		if _, err := os.Stat(configPath); err == nil {
			return fmt.Errorf("config already exists at %s (use --force to overwrite)", configPath)
		}
		defaultCfg, err := config.DefaultConfigYAML()
		if err != nil {
			return err
		}
		if err := os.WriteFile(configPath, defaultCfg, 0600); err != nil {
			return err
		}
		fmt.Printf("Default config written to %s\n", configPath)
		return nil

	default:
		fmt.Println("Usage: trapline config <check|show|init>")
		return nil
	}
}

func cmdBench(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	eng := buildEngine(cfg, nil)
	if err := eng.Init(); err != nil {
		return err
	}

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Println(tui.FormatSection("Benchmark"))
		fmt.Println()
	}

	mc := eng.Metrics()
	ctx := context.Background()
	passes := 3

	for i := 1; i <= passes; i++ {
		if tui.IsTTY() {
			fmt.Printf("  Pass %d/%d...\n", i, passes)
		}
		// Time each module individually
		for _, name := range eng.EnabledModules() {
			start := time.Now()
			findings, _ := eng.ScanModule(ctx, name)
			mc.Record(name, time.Since(start), len(findings))
		}
	}

	if tui.IsTTY() {
		fmt.Println()
		fmt.Println(tui.FormatSection("Results"))
		fmt.Println()
	}
	fmt.Print(mc.FormatSummary())
	return nil
}

func cmdServer(args []string) error {
	addr := envOrDefault("ADDR", ":8080")
	dataDir := envOrDefault("DATA_DIR", "/var/lib/trapline/server")
	password := os.Getenv("PASSWORD")
	publishSecrets := os.Getenv("PUBLISH_SECRETS")
	webRoot := os.Getenv("WEB_ROOT")

	for i, arg := range args {
		if (arg == "--addr" || arg == "--listen") && i+1 < len(args) {
			addr = args[i+1]
		}
		if arg == "--data" && i+1 < len(args) {
			dataDir = args[i+1]
		}
		if arg == "--password" && i+1 < len(args) {
			password = args[i+1]
		}
		if arg == "--publish-secrets" && i+1 < len(args) {
			publishSecrets = args[i+1]
		}
		if arg == "--web-root" && i+1 < len(args) {
			webRoot = args[i+1]
		}
	}

	var secrets []string
	if publishSecrets != "" {
		secrets = strings.Split(publishSecrets, ",")
	}

	srv, err := server.New(server.Config{
		Addr:           addr,
		DataDir:        dataDir,
		Password:       password,
		PublishSecrets: secrets,
		WebRoot:        webRoot,
	})
	if err != nil {
		return err
	}
	defer srv.Close()

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Println(tui.FormatSection("Dashboard Server"))
		fmt.Println()
		fmt.Printf("  %s Listening on %s\n", tui.CheckMark(true), tui.Subtitle.Render(addr))
		fmt.Println()
		fmt.Println(tui.Dimmed.Render("  Configure agents to POST findings to http://<this-host>" + addr + "/api/findings"))
		fmt.Println(tui.Dimmed.Render("  with header: Authorization: Bearer <publish-secret>"))
	} else {
		fmt.Printf("Trapline dashboard server starting on %s\n", addr)
	}

	return srv.ListenAndServe()
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func cmdVersion(args []string) error {
	jsonOutput := false
	for _, arg := range args {
		if arg == "--json" {
			jsonOutput = true
		}
	}

	if jsonOutput {
		info := map[string]string{
			"version": version,
			"commit":  commit,
			"date":    date,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	if tui.IsTTY() {
		fmt.Println(tui.FormatBanner(version, taglines.Random()))
		fmt.Printf("  %s %s\n", tui.Dimmed.Render("Commit:"), commit)
		fmt.Printf("  %s %s\n", tui.Dimmed.Render("Built:"), date)
	} else {
		fmt.Printf("Trapline %s\n", version)
		fmt.Printf("  Commit: %s\n", commit)
		fmt.Printf("  Built:  %s\n", date)
	}

	return nil
}
