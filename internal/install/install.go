package install

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

const (
	BinaryPath     = "/usr/local/bin/trapline"
	ConfigDir      = "/etc/trapline"
	ConfigPath     = "/etc/trapline/trapline.yml"
	ModulesDir     = "/etc/trapline/modules.d"
	StateDir       = "/var/lib/trapline"
	BaselinesDir   = "/var/lib/trapline/baselines"
	StateSubDir    = "/var/lib/trapline/state"
	LogDir         = "/var/log/trapline"
	ServicePath    = "/usr/lib/systemd/system/trapline.service"
	AptHookPath    = "/etc/apt/apt.conf.d/99trapline"
	LockPath       = "/var/run/trapline.lock"
)

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

var AptHook = `DPkg::Post-Invoke { "trapline rebaseline --module packages --module file-integrity --quiet || true"; };
`

// Install performs a full installation of trapline.
func Install(version string, defaultConfig []byte, noStart bool) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("trapline only runs on Linux (current: %s)", runtime.GOOS)
	}

	if os.Getuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	// Check for systemd
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd not found — trapline requires systemd")
	}

	fmt.Println("Installing trapline", version, "...")

	// Copy binary
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding self: %w", err)
	}
	if self != BinaryPath {
		if _, err := os.Stat(BinaryPath); err == nil {
			// Backup existing
			os.Rename(BinaryPath, BinaryPath+".bak")
		}
		if err := copyBinary(self, BinaryPath); err != nil {
			return fmt.Errorf("copying binary: %w", err)
		}
		fmt.Printf("  ✓ Binary installed to %s\n", BinaryPath)
	} else {
		fmt.Printf("  ✓ Binary already at %s\n", BinaryPath)
	}

	// Create directories
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

	// Write default config (only if not exists)
	if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
		if err := os.WriteFile(ConfigPath, defaultConfig, 0600); err != nil {
			return fmt.Errorf("writing config: %w", err)
		}
		fmt.Printf("  ✓ Config written to %s\n", ConfigPath)
	} else {
		fmt.Printf("  ✓ Config preserved at %s\n", ConfigPath)
	}

	// Write systemd unit (always overwrite — owned by binary)
	if err := os.MkdirAll("/usr/lib/systemd/system", 0755); err != nil {
		return fmt.Errorf("creating systemd dir: %w", err)
	}
	if err := os.WriteFile(ServicePath, []byte(SystemdUnit), 0644); err != nil {
		return fmt.Errorf("writing systemd unit: %w", err)
	}
	fmt.Println("  ✓ Systemd unit installed")

	// Install apt hook (if dpkg exists)
	if _, err := exec.LookPath("dpkg"); err == nil {
		os.WriteFile(AptHookPath, []byte(AptHook), 0644)
		fmt.Println("  ✓ Apt hook installed")
	}

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "trapline").Run()
	fmt.Println("  ✓ Service enabled")

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

// Uninstall removes trapline completely.
func Uninstall(keepConfig bool) error {
	if os.Getuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	fmt.Println("Uninstalling trapline...")

	// Stop and disable service
	exec.Command("systemctl", "stop", "trapline").Run()
	exec.Command("systemctl", "disable", "trapline").Run()
	fmt.Println("  ✓ Service stopped and disabled")

	// Remove systemd unit
	os.Remove(ServicePath)
	exec.Command("systemctl", "daemon-reload").Run()
	fmt.Println("  ✓ Systemd unit removed")

	// Remove apt hook
	os.Remove(AptHookPath)

	// Remove state and logs
	os.RemoveAll(StateDir)
	fmt.Println("  ✓ State and baselines removed")

	os.RemoveAll(LogDir)
	fmt.Println("  ✓ Logs removed")

	// Remove config (unless --keep-config)
	if !keepConfig {
		os.RemoveAll(ConfigDir)
		fmt.Println("  ✓ Configuration removed")
	} else {
		fmt.Printf("  ✓ Configuration preserved at %s\n", ConfigDir)
	}

	// Remove binary
	os.Remove(BinaryPath)
	os.Remove(BinaryPath + ".bak")
	os.Remove(LockPath)
	fmt.Println("  ✓ Binary removed")

	fmt.Println("\nTrapline has been completely uninstalled.")
	return nil
}

func copyBinary(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0755); err != nil {
		return err
	}
	return os.Chmod(dst, 0755)
}
