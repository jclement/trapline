// Package install implements Trapline's self-installing binary pattern. Rather
// than distributing a separate installer script or package (.deb/.rpm), the
// trapline binary IS the installer: running "trapline install" copies itself
// to the canonical path, creates all required directories, writes a default
// config, installs a systemd unit, and optionally starts the service.
//
// This "binary is the installer" philosophy has several advantages:
//
//   - Single artifact to distribute: one static binary for download, CI, or
//     air-gapped environments.
//   - Idempotent: every step checks whether the target already exists before
//     acting, so re-running "trapline install" is always safe.
//   - Version-matched: the systemd unit and apt hook embedded in the binary
//     are guaranteed to match the binary's version.
//   - Uninstall is symmetric: "trapline uninstall" reverses every step.
//
// Embedded assets (SystemdUnit, AptHook) are defined as Go string literals
// rather than go:embed because they are small and benefit from being visible
// in the source alongside the install logic.
//
// Backup strategy: when overwriting an existing binary, the old binary is
// renamed to /usr/local/bin/trapline.bak before the new one is written. This
// provides a one-version rollback safety net.
package install

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Filesystem paths used by Trapline. These constants define the canonical
// locations for every artifact on a Linux system, following FHS conventions:
//
//   - /usr/local/bin: user-installed binaries (outside package manager)
//   - /etc/trapline: configuration files (root-only, mode 0700)
//   - /var/lib/trapline: persistent state and baselines (root-only, mode 0700)
//   - /var/log/trapline: log files (mode 0750 so log readers can access)
//   - /usr/lib/systemd/system: system-wide systemd units
//   - /etc/apt/apt.conf.d: APT hook configuration (Debian/Ubuntu only)
//   - /var/run: runtime lock file to prevent concurrent trapline processes
const (
	BinaryPath   = "/usr/local/bin/trapline"
	ConfigDir    = "/etc/trapline"
	ConfigPath   = "/etc/trapline/trapline.yml"
	ModulesDir   = "/etc/trapline/modules.d"
	StateDir     = "/var/lib/trapline"
	BaselinesDir = "/var/lib/trapline/baselines"
	StateSubDir  = "/var/lib/trapline/state"
	LogDir       = "/var/log/trapline"
	ServicePath  = "/usr/lib/systemd/system/trapline.service"
	AptHookPath  = "/etc/apt/apt.conf.d/99trapline"
	LockPath     = "/var/run/trapline.lock"
)

// SystemdUnit is the systemd service unit file installed to ServicePath. Key
// design decisions:
//
//   - Type=simple: trapline runs as a long-lived foreground process.
//   - After=network.target docker.service: ensures network is up and Docker
//     is available for the containers module.
//   - Restart=on-failure with StartLimitBurst=5/300s: auto-restarts on crash
//     but gives up after 5 failures in 5 minutes to avoid tight restart loops.
//   - ProtectSystem=strict + ReadWritePaths: systemd security hardening that
//     makes the filesystem read-only except for the specific paths trapline
//     needs to write (state, logs, lock file).
//   - ProtectHome=read-only: allows the ssh module to read ~/.ssh but prevents
//     writes to home directories.
//   - WatchdogSec=120: systemd will kill and restart trapline if it stops
//     responding for 2 minutes (requires sd_notify integration).
var SystemdUnit = `[Unit]
Description=Trapline host integrity monitor
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/trapline run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=300

ProtectSystem=strict
ReadWritePaths=/var/lib/trapline /var/log/trapline /var/run
ProtectHome=read-only
PrivateTmp=true

WatchdogSec=120

[Install]
WantedBy=multi-user.target
`

// AptHook is a DPkg::Post-Invoke hook installed on Debian/Ubuntu systems. It
// triggers an automatic rebaseline of the "packages" and "file-integrity"
// modules after every apt install/upgrade/remove operation. This prevents
// legitimate package changes from generating false-positive findings. The
// trailing "|| true" ensures apt never fails due to a trapline error.
var AptHook = `DPkg::Post-Invoke { "trapline rebaseline --module packages --module file-integrity --quiet || true"; };
`

// Install performs a full installation of trapline on the current system. The
// steps are executed in order; each step is idempotent so re-running install
// is always safe:
//
//  1. Platform guard: only Linux with systemd is supported.
//  2. Root check: installation modifies system directories.
//  3. Copy binary: resolves os.Executable() and copies itself to BinaryPath.
//     If a binary already exists there, it is backed up to BinaryPath+".bak"
//     before overwriting, providing a one-version rollback.
//  4. Create directories: all required directories with appropriate permissions
//     (0700 for security-sensitive dirs, 0750 for logs).
//  5. Write default config: only if ConfigPath does not already exist, to
//     preserve operator customizations across upgrades.
//  6. Install systemd unit: always overwritten because it is owned by the
//     binary and must match the current version's expectations.
//  7. Install apt hook: only on Debian/Ubuntu systems (detected by dpkg).
//  8. Enable and optionally start the systemd service.
//
// The version parameter is used for display only. The defaultConfig parameter
// is the YAML bytes to write as the initial configuration (typically from
// [config.DefaultConfigYAML]). Set noStart to true to install without
// immediately starting the service.
func Install(version string, defaultConfig []byte, noStart bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("trapline only runs on Linux (current: %s)", runtime.GOOS)
	}

	if os.Getuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	// Check for systemd by probing the well-known runtime directory. If this
	// directory does not exist, the system is not running systemd and trapline
	// cannot be installed as a service.
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd not found — trapline requires systemd")
	}

	fmt.Println("Installing trapline", version, "...")

	// Step 1: Copy the currently running binary to the canonical install path.
	// os.Executable() resolves symlinks, so this works regardless of how the
	// user invoked the binary (e.g. ./trapline, /tmp/trapline, etc.).
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding self: %w", err)
	}
	if self != BinaryPath {
		if _, err := os.Stat(BinaryPath); err == nil {
			// Backup the existing binary for rollback. This is a simple rename
			// rather than a copy to avoid doubling disk usage for large binaries.
			_ = os.Rename(BinaryPath, BinaryPath+".bak")
		}
		if err := copyBinary(self, BinaryPath); err != nil {
			return fmt.Errorf("copying binary: %w", err)
		}
		fmt.Printf("  ✓ Binary installed to %s\n", BinaryPath)
	} else {
		// Already running from the canonical path — skip the copy.
		fmt.Printf("  ✓ Binary already at %s\n", BinaryPath)
	}

	// Step 2: Create all required directories with appropriate permissions.
	// Security-sensitive directories (config, state, baselines) use 0700
	// (root-only). The log directory uses 0750 to allow membership in a
	// log-reader group.
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{ConfigDir, 0700},
		{ModulesDir, 0700},
		{StateDir, 0700},
		{BaselinesDir, 0700},
		{StateSubDir, 0700},
		{LogDir, 0750},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("creating %s: %w", d.path, err)
		}
	}
	fmt.Println("  ✓ Directories created")

	// Step 3: Write the default config only if no config exists yet. This
	// preserves any operator customizations across re-installs and upgrades.
	if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
		if err := os.WriteFile(ConfigPath, defaultConfig, 0600); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}
		fmt.Printf("  ✓ Config written to %s\n", ConfigPath)
	} else {
		fmt.Printf("  ✓ Config preserved at %s\n", ConfigPath)
	}

	// Step 4: Write the systemd unit file. Unlike the config, this is always
	// overwritten because the unit file is "owned" by the binary — its contents
	// must match the binary's version (e.g. ExecStart path, security settings).
	if err := os.MkdirAll("/usr/lib/systemd/system", 0755); err != nil {
		return fmt.Errorf("creating systemd dir: %w", err)
	}
	if err := os.WriteFile(ServicePath, []byte(SystemdUnit), 0644); err != nil {
		return fmt.Errorf("writing systemd unit: %w", err)
	}
	fmt.Println("  ✓ Systemd unit installed")

	// Step 5: Install the APT post-invoke hook on Debian/Ubuntu systems. The
	// hook triggers automatic rebaseline after package operations. On non-dpkg
	// systems this step is silently skipped.
	if _, err := exec.LookPath("dpkg"); err == nil {
		_ = os.WriteFile(AptHookPath, []byte(AptHook), 0644)
		fmt.Println("  ✓ Apt hook installed")
	}

	// Step 6: Reload systemd to pick up the new/updated unit file, then
	// enable the service so it starts automatically on boot.
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "trapline").Run()
	fmt.Println("  ✓ Service enabled")

	// Step 7: Optionally start the service immediately. The noStart flag
	// allows "install without starting" for CI or image-baking scenarios.
	if !noStart {
		if err := exec.Command("systemctl", "start", "trapline").Run(); err != nil {
			fmt.Printf("  ⚠ Failed to start service: %v\n", err)
			fmt.Println("    Start manually with: systemctl start trapline")
		} else {
			fmt.Println("  ✓ Service started")
		}
	}

	fmt.Printf("\nTrapline %s is installed. Check status with: trapline status\n", version)
	return nil
}

// Uninstall removes trapline completely from the system, reversing every step
// performed by [Install]. The keepConfig flag allows operators to preserve
// their configuration for a future reinstall.
//
// Removal order is deliberately the reverse of installation: stop the service
// first, then remove files. This ensures the running process does not try to
// access files as they are being deleted.
func Uninstall(keepConfig bool) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	fmt.Println("Uninstalling trapline...")

	// Stop and disable the systemd service before removing any files.
	_ = exec.Command("systemctl", "stop", "trapline").Run()
	_ = exec.Command("systemctl", "disable", "trapline").Run()
	fmt.Println("  ✓ Service stopped and disabled")

	// Remove the systemd unit file and reload the daemon so systemd forgets
	// about the service entirely.
	_ = os.Remove(ServicePath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("  ✓ Systemd unit removed")

	// Remove the APT hook (no-op if it was never installed).
	_ = os.Remove(AptHookPath)

	// Remove state directory (baselines, locks, scanner state).
	_ = os.RemoveAll(StateDir)
	fmt.Println("  ✓ State and baselines removed")

	// Remove log files.
	_ = os.RemoveAll(LogDir)
	fmt.Println("  ✓ Logs removed")

	// Remove configuration only if the operator has not requested preservation.
	// Keeping config allows a quick reinstall with the same settings.
	if !keepConfig {
		_ = os.RemoveAll(ConfigDir)
		fmt.Println("  ✓ Configuration removed")
	} else {
		fmt.Printf("  ✓ Configuration preserved at %s\n", ConfigDir)
	}

	// Remove the binary, its backup, and the runtime lock file.
	_ = os.Remove(BinaryPath)
	_ = os.Remove(BinaryPath + ".bak")
	_ = os.Remove(LockPath)
	fmt.Println("  ✓ Binary removed")

	fmt.Println("\nTrapline has been completely uninstalled.")
	return nil
}

// copyBinary reads the source binary into memory and writes it to the
// destination path with mode 0755 (executable by all, writable by owner).
// This is used instead of os.Link or os.Rename because the source and
// destination may be on different filesystems (e.g. /tmp vs /usr/local/bin).
func copyBinary(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0755); err != nil {
		return err
	}
	// Explicitly chmod to ensure the mode is correct even if umask interfered.
	return os.Chmod(dst, 0755)
}
