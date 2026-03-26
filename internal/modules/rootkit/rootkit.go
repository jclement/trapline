// Package rootkit implements last-line-of-defense rootkit detection by looking
// for system anomalies that are difficult for rootkits to conceal.
//
// # What It Monitors and Why
//
// Rootkits are the most dangerous class of compromise because they actively
// subvert the operating system to hide attacker activity. Once a rootkit is
// installed, other security modules (file integrity, process monitoring) may
// be blind because the rootkit hooks syscalls to hide files, processes, and
// network connections. This module focuses on indicators that are inherently
// hard for userspace (and many kernel) rootkits to suppress:
//
//   - Kernel module changes: new modules appearing after baseline indicate
//     a loadable kernel module (LKM) rootkit or attacker tool being loaded.
//   - Promiscuous network interfaces: a NIC in promiscuous mode means something
//     is sniffing all traffic, which is a hallmark of credential harvesting.
//   - Regular files in /dev: legitimate /dev entries are device nodes and
//     symlinks; regular files indicate hidden data stashes or rootkit components.
//   - Hidden dotfiles in /tmp, /var/tmp, /dev/shm: attackers frequently drop
//     tools and staging files as dotfiles in world-writable directories.
//   - Processes running from deleted binaries: a running process whose on-disk
//     binary has been removed is a classic indicator of fileless malware or
//     an attacker covering their tracks after deployment.
//
// # How It Works
//
// Data sources are all procfs/sysfs based (/proc/modules, /proc/net,
// /sys/class/net/*/flags, /proc/*/exe) plus direct directory listing of
// /dev and tmp directories. Kernel module names are compared against a
// persisted baseline using the baseline.Store; the first scan auto-learns.
// Other checks are stateless and fire on any match.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - T1014 (Rootkit): new kernel modules, deleted-exe processes
//   - T1040 (Network Sniffing): promiscuous interface detection
//   - T1059.004 (Unix Shell): hidden tool drops in tmp directories
//   - T1070.004 (File Deletion): processes running from deleted binaries
//   - T1547.006 (Kernel Modules and Extensions): new kernel module loading
//   - T1564.001 (Hidden Files and Directories): dotfiles in tmp dirs,
//     regular files stashed in /dev
//
// # Known Limitations and Blind Spots
//
//   - A sophisticated kernel rootkit that hooks the readdir/open syscalls can
//     hide entries from /proc/modules, /dev, and /tmp listings entirely.
//   - eBPF-based rootkits that do not appear in /proc/modules are invisible.
//   - The kernel module check only detects NEW modules since baseline; it
//     cannot detect a module that was present at initial baseline time.
//   - Only scans the top-level of /dev and tmp dirs (not recursive).
//   - Promiscuous check reads sysfs flags; a rootkit that intercepts sysfs
//     reads could mask the IFF_PROMISC bit.
//   - Deleted-exe check relies on the " (deleted)" suffix in /proc/PID/exe
//     readlink output, which is a Linux kernel convention that could
//     theoretically change across kernel versions.
//
// # False Positive Risks
//
//   - Kernel module updates (e.g., DKMS rebuilds after kernel upgrades)
//     will trigger new-kernel-module alerts. Mitigate by rebaselining after
//     planned maintenance.
//   - Legitimate network monitoring tools (tcpdump, Wireshark) put interfaces
//     into promiscuous mode. Investigate the source process before escalating.
//   - Some applications create dotfiles in /tmp (e.g., .java_pid*). Add
//     known-good entries to the knownHiddenFiles allowlist.
//   - Short-lived package manager operations may briefly show deleted-exe
//     processes during upgrades (e.g., dpkg replacing a running daemon).
//
// # Performance Characteristics
//
// All checks are lightweight filesystem reads. The kernel modules check reads
// a single small file (/proc/modules). The deleted-exe check iterates /proc
// PID directories (one readlink per process). Total scan time is typically
// under 50ms on systems with fewer than 1000 processes.
//
// # Configuration
//
// Filesystem paths (ProcDir, SysDir, TmpDirs, DevDir) are struct fields that
// can be overridden for testing. No YAML/config file options are currently
// exposed; the module uses sensible defaults for production Linux systems.
package rootkit

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// knownHiddenFiles is an allowlist of dotfiles that are expected in /tmp and
// similar directories. These are created by the X Window System and related
// display protocols and are not indicators of compromise. Any dotfile NOT in
// this map will trigger an alert when found in a watched tmp directory.
var knownHiddenFiles = map[string]bool{
	".X11-unix":  true, // X11 display server socket directory
	".ICE-unix":  true, // Inter-Client Exchange protocol sockets
	".font-unix": true, // Font server sockets
	".XIM-unix":  true, // X Input Method sockets
}

// Module implements rootkit detection checks by examining procfs, sysfs, and
// filesystem artifacts that are difficult for rootkits to hide. It maintains
// a baseline of kernel modules and alerts on deviations.
type Module struct {
	store *baseline.Store

	// Configurable filesystem paths — defaults point to real system paths;
	// overridden in tests to use temporary directories with controlled content.
	ProcDir string
	SysDir  string
	TmpDirs []string
	DevDir  string
}

// New creates a new rootkit detection module with production filesystem paths.
// All paths can be overridden after construction for testing.
func New() *Module {
	return &Module{
		ProcDir: "/proc",
		SysDir:  "/sys",
		TmpDirs: []string{"/tmp", "/var/tmp", "/dev/shm"},
		DevDir:  "/dev",
	}
}

func (m *Module) Name() string { return "rootkit" }

// Init sets up the baseline store for persisting kernel module lists across
// scan cycles. The baseline store is the only stateful component; all other
// checks are stateless and fire on direct observation.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	return nil
}

// kernelBaseline is the structure persisted for kernel module baselining.
// We store a simple set of module names (not versions or sizes) because
// the presence of a NEW module is the threat signal, not changes to
// existing module metadata.
type kernelBaseline struct {
	Modules map[string]bool `json:"modules"`
}

// Scan runs all five rootkit detection checks in sequence and aggregates
// their findings. Each check is independent and non-fatal: if one check
// fails (e.g., /proc/modules unreadable), the others still execute.
// This resilience matters because a partially compromised system may have
// some procfs files restricted.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	var findings []finding.Finding

	// 1. Kernel modules check — detects LKM rootkits and attacker tools
	kf, err := m.checkKernelModules()
	if err == nil {
		findings = append(findings, kf...)
	}
	// Intentionally swallow the error: if /proc/modules is unreadable, we
	// still want the remaining checks to run.

	// 2. Hidden files in tmp dirs — catches attacker tool staging
	hf := m.checkHiddenFiles()
	findings = append(findings, hf...)

	// 3. Regular files in /dev — catches data stashes and rootkit components
	df := m.checkDevFiles()
	findings = append(findings, df...)

	// 4. Promiscuous interfaces — catches network sniffing
	pf := m.checkPromiscuous()
	findings = append(findings, pf...)

	// 5. Deleted exe processes — catches fileless malware and anti-forensics
	ef := m.checkDeletedExe()
	findings = append(findings, ef...)

	return findings, nil
}

// Rebaseline captures the current set of kernel modules as the new known-good
// state. This should be called after planned maintenance (kernel upgrades,
// module installations) to prevent false positives on subsequent scans.
func (m *Module) Rebaseline(ctx context.Context) error {
	modules, err := m.readKernelModules()
	if err != nil {
		return err
	}
	bl := kernelBaseline{Modules: modules}
	return m.store.Save(m.Name(), &bl)
}

// checkKernelModules reads /proc/modules and compares against baseline.
// This is the only stateful check in the rootkit module. On first run it
// auto-learns the current module set; on subsequent runs it alerts on any
// module name that was not present at baseline time. This catches LKM-based
// rootkits (e.g., Diamorphine, Reptile) that load kernel modules to hook
// syscalls and hide processes/files.
func (m *Module) checkKernelModules() ([]finding.Finding, error) {
	current, err := m.readKernelModules()
	if err != nil {
		return nil, err
	}

	var bl kernelBaseline
	exists, err := m.store.Load(m.Name(), &bl)
	if err != nil {
		return nil, err
	}

	if !exists {
		// Learning mode: no baseline exists yet, so save the current state
		// as known-good and suppress all findings. This prevents a flood of
		// alerts on first deployment.
		bl = kernelBaseline{Modules: current}
		if err := m.store.Save(m.Name(), &bl); err != nil {
			return nil, err
		}
		return nil, nil
	}

	var findings []finding.Finding
	for mod := range current {
		if !bl.Modules[mod] {
			// A kernel module exists now that was not present at baseline time.
			// This is SeverityHigh because kernel modules have full ring-0
			// access and can subvert any userspace security control.
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "new-kernel-module:" + mod,
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new kernel module loaded: %s", mod),
				Detail: map[string]interface{}{
					"module": mod,
				},
			})
		}
	}

	return findings, nil
}

// readKernelModules parses /proc/modules and returns a set of module names.
// The /proc/modules format is space-delimited with the module name as the
// first field: "module_name size refcount dependencies state address"
// We only care about the name; size/refcount/state are not security-relevant
// for our detection model (presence of a new name is the signal).
func (m *Module) readKernelModules() (map[string]bool, error) {
	path := filepath.Join(m.ProcDir, "modules")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	modules := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Extract just the module name (first whitespace-delimited field)
		fields := strings.Fields(line)
		if len(fields) > 0 {
			modules[fields[0]] = true
		}
	}
	return modules, scanner.Err()
}

// checkHiddenFiles scans tmp dirs for suspicious dotfiles.
// Attackers commonly drop tools, exploits, and staging data as dotfiles in
// world-writable directories because: (a) they're hidden from casual `ls`
// output, (b) tmp dirs have permissive write access, and (c) they persist
// across user sessions. We check /tmp, /var/tmp, and /dev/shm by default.
// Known-legitimate dotfiles (X11 sockets, etc.) are allowlisted.
func (m *Module) checkHiddenFiles() []finding.Finding {
	var findings []finding.Finding
	for _, dir := range m.TmpDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Directory may not exist or may be unreadable; skip silently
			// since not all systems have all tmp dirs.
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			// Only interested in dotfiles (hidden by convention)
			if !strings.HasPrefix(name, ".") {
				continue
			}
			// Skip the directory self-references (should not appear in ReadDir
			// output, but defensive check)
			if name == "." || name == ".." {
				continue
			}
			// Skip known-legitimate dotfiles (X11 sockets, font sockets, etc.)
			if knownHiddenFiles[name] {
				continue
			}
			fullPath := filepath.Join(dir, name)
			// SeverityMedium because hidden files in tmp are suspicious but
			// have legitimate explanations (Java PID files, editor swap files).
			// An analyst should investigate the file contents and owning process.
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "hidden-file:" + fullPath,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("hidden file in %s: %s", dir, name),
				Detail: map[string]interface{}{
					"path": fullPath,
					"dir":  dir,
				},
			})
		}
	}
	return findings
}

// checkDevFiles looks for regular files in /dev.
// The /dev directory should contain only device nodes (block/char), symlinks,
// and directories — never regular files. A regular file in /dev is a strong
// indicator of either: (a) a rootkit hiding components where admins rarely
// look, (b) an attacker stashing exfiltrated data or tools, or (c) a
// persistent backdoor (some rootkits create /dev/.hidden_backdoor).
// This is SeverityHigh because there is almost no legitimate reason for
// regular files to exist in /dev on a properly configured system.
func (m *Module) checkDevFiles() []finding.Finding {
	var findings []finding.Finding
	entries, err := os.ReadDir(m.DevDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		// Only flag regular files — device nodes (char/block), directories,
		// and symlinks are all expected in /dev and should be ignored.
		if !entry.Type().IsRegular() {
			continue
		}
		fullPath := filepath.Join(m.DevDir, entry.Name())
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "dev-regular-file:" + fullPath,
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("regular file in /dev: %s", entry.Name()),
			Detail: map[string]interface{}{
				"path": fullPath,
			},
		})
	}
	return findings
}

// checkPromiscuous reads network interface flags and checks for IFF_PROMISC (0x100).
// A network interface in promiscuous mode receives ALL packets on the network
// segment, not just those addressed to it. This is the hallmark of packet
// sniffing — an attacker capturing credentials, session tokens, or other
// sensitive data in transit. Legitimate uses include network monitoring tools
// (tcpdump, Wireshark), but on a production server these should not be running.
// This is SeverityCritical because promiscuous mode enables credential theft
// and man-in-the-middle attacks on the local network segment.
func (m *Module) checkPromiscuous() []finding.Finding {
	var findings []finding.Finding
	// Each network interface exposes its flags via sysfs at
	// /sys/class/net/<iface>/flags as a hex string (e.g., "0x1003").
	netDir := filepath.Join(m.SysDir, "class", "net")
	ifaces, err := os.ReadDir(netDir)
	if err != nil {
		return nil
	}
	for _, iface := range ifaces {
		flagsPath := filepath.Join(netDir, iface.Name(), "flags")
		data, err := os.ReadFile(flagsPath)
		if err != nil {
			continue
		}
		flagStr := strings.TrimSpace(string(data))
		// Parse the hex flags value (e.g., "0x1103" -> 0x1103)
		flags, err := strconv.ParseUint(strings.TrimPrefix(flagStr, "0x"), 16, 64)
		if err != nil {
			continue
		}
		// IFF_PROMISC is bit 8 (0x100) in the kernel's net_device flags.
		// This is defined in include/uapi/linux/if.h and is stable across
		// kernel versions.
		if flags&0x100 != 0 {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "promiscuous-interface:" + iface.Name(),
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("network interface %s is in promiscuous mode", iface.Name()),
				Detail: map[string]interface{}{
					"interface": iface.Name(),
					"flags":     flagStr,
				},
			})
		}
	}
	return findings
}

// checkDeletedExe looks for processes whose binary has been deleted from disk.
// This is a classic anti-forensics technique: an attacker executes a binary,
// then deletes it to remove evidence. The process continues running in memory
// (Linux keeps the inode alive while the file descriptor is open), but the
// /proc/PID/exe symlink will show the original path with " (deleted)" appended.
//
// This catches:
//   - Fileless malware that self-deletes after execution
//   - Attackers cleaning up after deploying implants
//   - Memfd-based execution where the binary was staged temporarily
//
// SeverityCritical because a running process with no on-disk binary is
// extremely suspicious and indicates active compromise in most cases.
// Note: legitimate false positives can occur during package upgrades when
// dpkg/rpm replaces a binary while its old version is still running.
func (m *Module) checkDeletedExe() []finding.Finding {
	var findings []finding.Finding
	entries, err := os.ReadDir(m.ProcDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Filter to numeric PID directories; skip /proc/sys, /proc/net, etc.
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		// /proc/PID/exe is a symlink to the process's executable. If the
		// file has been deleted, the kernel appends " (deleted)" to the
		// symlink target.
		exePath := filepath.Join(m.ProcDir, entry.Name(), "exe")
		target, err := os.Readlink(exePath)
		if err != nil {
			// Permission denied for other users' processes, or the process
			// may have exited between readdir and readlink — both are benign.
			continue
		}
		if strings.HasSuffix(target, " (deleted)") {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "deleted-exe:" + entry.Name(),
				Severity:  finding.SeverityCritical,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("process %s running with deleted binary", entry.Name()),
				Detail: map[string]interface{}{
					"pid": entry.Name(),
					"exe": target,
				},
			})
		}
	}
	return findings
}
