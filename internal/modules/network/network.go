// Package network implements outbound connection monitoring to detect
// command-and-control (C2) beacons, data exfiltration, and unauthorized
// network activity by baselining known remote IP addresses.
//
// # What It Monitors and Why
//
// Even if an attacker evades file-based detection (no malware on disk,
// living-off-the-land techniques), they almost always need to communicate
// with external infrastructure for C2, data exfiltration, or tool download.
// This module reads the kernel's TCP connection table (/proc/net/tcp and
// /proc/net/tcp6) and alerts when the system establishes connections to
// previously unseen public IP addresses.
//
// # How It Works
//
//  1. Parses /proc/net/tcp and /proc/net/tcp6 for ESTABLISHED connections
//     (state field == 0x01 in the kernel's hex encoding).
//  2. Extracts remote IP addresses, converting from the kernel's hex
//     little-endian format to human-readable notation.
//  3. Filters out private (RFC1918), loopback, link-local, and unspecified
//     addresses to focus on external/internet-facing connections.
//  4. Resolves the owning process for each connection by scanning
//     /proc/<pid>/fd/ symlinks for matching socket inodes.
//  5. Filters out connections from allowlisted processes (e.g., apt, dpkg).
//  6. Compares the set of unique public remote IPs against the persisted
//     baseline of known-good IPs.
//  7. Generates findings for any IP not in the baseline, including the
//     owning process name in the alert.
//
// The first scan auto-learns the baseline. Subsequent scans only alert on
// new destinations.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - T1071 (Application Layer Protocol): C2 over HTTP/HTTPS to new IPs
//   - T1041 (Exfiltration Over C2 Channel): data theft to attacker infrastructure
//   - T1105 (Ingress Tool Transfer): downloading additional tools from new IPs
//   - T1572 (Protocol Tunneling): tunneled connections show as new TCP endpoints
//   - T1219 (Remote Access Software): unexpected remote access tool connections
//   - T1048 (Exfiltration Over Alternative Protocol): any TCP-based exfiltration
//
// # Known Limitations and Blind Spots
//
//   - UDP connections are NOT monitored (would require /proc/net/udp parsing).
//     DNS exfiltration over UDP/53 is invisible to this module.
//   - Only captures a point-in-time snapshot; short-lived connections between
//     scan intervals will be missed entirely.
//   - Process-to-connection correlation is best-effort; short-lived processes
//     may exit before the /proc/<pid>/fd/ scan completes (TOCTOU).
//   - CDN and cloud provider IPs rotate frequently (AWS, CloudFront, Akamai),
//     which can cause a steady stream of new-IP alerts for legitimate traffic.
//   - An attacker reusing an IP already in the baseline (e.g., compromising
//     a legitimate service the host already talks to) is invisible.
//   - IPv6-mapped IPv4 addresses may appear as different IPs than their
//     IPv4 equivalents, causing duplicate or missed correlations.
//
// # False Positive Risks
//
//   - CDN IP rotation is the primary source of false positives. Services like
//     AWS CloudFront, Akamai, and Fastly use large IP pools. Mitigate by
//     rebaselining periodically or implementing CIDR-based allowlisting
//     (not currently supported).
//   - Software updates contacting new mirror IPs will trigger alerts.
//   - Auto-scaling cloud services (e.g., new database replicas) introduce
//     new IPs legitimately.
//
// # Performance Characteristics
//
// Extremely lightweight: reads two small procfs files and performs string
// parsing. No network I/O, no DNS lookups, no process enumeration. Typical
// scan completes in under 5ms regardless of system load. Memory usage is
// proportional to the number of established TCP connections (typically
// hundreds, rarely thousands).
//
// # Configuration Options
//
//   - allowed_processes ([]string): List of process names whose outbound
//     connections are silently ignored. Matching is case-insensitive.
//     Useful for package managers (apt, dpkg), AV updaters (freshclam),
//     and other tools that contact many transient IPs.
//   - ProcTCP, ProcTCP6 (string): override the paths to /proc/net/tcp and
//     /proc/net/tcp6 for testing with synthetic data.
//   - ProcDir (string): Path to /proc, overridable for testing.
package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// Connection represents a single parsed TCP connection from the kernel's
// /proc/net/tcp connection table. Only ESTABLISHED connections are captured
// since other states (LISTEN, TIME_WAIT, etc.) are not indicative of active
// outbound communication.
type Connection struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	Inode      string `json:"inode"`
}

// NetworkBaseline stores the set of known-good remote IPs that have been
// observed in previous scans. Any public IP not in this set triggers an alert.
type NetworkBaseline struct {
	KnownRemoteIPs map[string]bool `json:"known_remote_ips"`
	Initialized    bool            `json:"initialized"`
}

// Module monitors established outbound TCP connections by reading the kernel's
// connection table from procfs and comparing remote IPs against a learned baseline.
type Module struct {
	store            *baseline.Store
	baseline         NetworkBaseline
	baselineLoaded   bool
	allowedProcesses []string
	// ProcTCP and ProcTCP6 can be overridden to point at test fixtures
	// instead of the real /proc/net/tcp files.
	ProcTCP  string
	ProcTCP6 string
	// ProcDir is the path to /proc, used for process-to-connection correlation
	// via /proc/<pid>/fd/ symlinks. Exported for testing.
	ProcDir string
}

// New creates a new network module pointing at the real procfs TCP tables.
func New() *Module {
	return &Module{
		ProcTCP:  "/proc/net/tcp",
		ProcTCP6: "/proc/net/tcp6",
		ProcDir:  "/proc",
	}
}

func (m *Module) Name() string { return "network" }

// Init loads the persisted baseline of known-good remote IPs. If no baseline
// exists yet, baselineLoaded will be false and the first Scan() call will
// enter learning mode.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)

	// Parse allowed_processes from config. Connections owned by these processes
	// are silently ignored, which is useful for package managers (apt, dpkg),
	// AV updaters (freshclam), and other tools that contact many transient IPs.
	if apRaw, ok := cfg.Settings["allowed_processes"]; ok {
		if apList, ok := apRaw.([]interface{}); ok {
			for _, e := range apList {
				if name, ok := e.(string); ok {
					m.allowedProcesses = append(m.allowedProcesses, name)
				}
			}
		}
	}

	return nil
}

// processInfo holds the result of resolving a socket inode to its owning process.
type processInfo struct {
	Name string
	PID  int
}

// buildInodeMap scans all /proc/<pid>/fd/ entries and returns a map from socket
// inode string to the owning process info. Called once per scan cycle to avoid
// redundant /proc traversals. All errors are silently ignored since processes
// may exit between steps (TOCTOU).
func buildInodeMap(procDir string) map[string]processInfo {
	result := make(map[string]processInfo)
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join(procDir, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		// Lazy-load comm only if we find a socket fd.
		var procName string
		var commLoaded bool

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
				continue
			}
			inode := link[8 : len(link)-1]
			if !commLoaded {
				comm, err := os.ReadFile(filepath.Join(procDir, entry.Name(), "comm"))
				if err != nil {
					break
				}
				procName = strings.TrimSpace(string(comm))
				commLoaded = true
			}
			result[inode] = processInfo{Name: procName, PID: pid}
		}
	}

	return result
}

// isAllowedProcess returns true if the process name matches any entry in the
// allowed_processes config list. Matching is case-insensitive.
func (m *Module) isAllowedProcess(name string) bool {
	for _, allowed := range m.allowedProcesses {
		if strings.EqualFold(name, allowed) {
			return true
		}
	}
	return false
}

// Scan reads the current TCP connection table, extracts unique public remote
// IPs, and compares them against the baseline. New IPs generate findings.
// The severity escalation logic (single new IP = High, multiple = Critical)
// is based on the observation that a single new connection might be a
// legitimate new service, but multiple simultaneous new connections are more
// likely to indicate C2 beaconing or port scanning activity.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	conns, err := m.scanConnections()
	if err != nil {
		return nil, err
	}

	// Build inode-to-process map once for this scan cycle.
	inodeMap := buildInodeMap(m.ProcDir)

	// Build a deduplicated map of public remote IPs with process info.
	// Filter out private/loopback IPs and connections from allowlisted processes.
	currentIPs := make(map[string]Connection)
	processMap := make(map[string]processInfo)
	for _, c := range conns {
		if isPrivateIP(c.RemoteAddr) {
			continue
		}
		if _, exists := currentIPs[c.RemoteAddr]; exists {
			continue
		}
		// Resolve owning process via inode.
		if proc, ok := inodeMap[c.Inode]; ok {
			if m.isAllowedProcess(proc.Name) {
				continue
			}
			processMap[c.RemoteAddr] = proc
		}
		currentIPs[c.RemoteAddr] = c
	}

	// Learning mode: first scan records all current public IPs as known-good.
	// This prevents a flood of alerts on initial deployment since all existing
	// connections are assumed legitimate until proven otherwise.
	if !m.baselineLoaded || !m.baseline.Initialized {
		m.baseline = NetworkBaseline{
			KnownRemoteIPs: make(map[string]bool),
			Initialized:    true,
		}
		for ip := range currentIPs {
			m.baseline.KnownRemoteIPs[ip] = true
		}
		m.baselineLoaded = true
		_ = m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	// Detect new outbound IPs that are not in the known-good baseline.
	var newIPs []string
	for ip := range currentIPs {
		if !m.baseline.KnownRemoteIPs[ip] {
			newIPs = append(newIPs, ip)
		}
	}

	if len(newIPs) == 0 {
		return nil, nil
	}

	var findings []finding.Finding

	// Severity escalation: a single new IP is noteworthy (Medium) but could
	// be a legitimate new service. Multiple simultaneous new IPs are more
	// concerning (High) as they suggest C2 burst or scanning activity.
	severity := finding.SeverityMedium
	if len(newIPs) > 1 {
		severity = finding.SeverityHigh
	}

	for _, ip := range newIPs {
		conn := currentIPs[ip]
		proc := processMap[ip]
		procName := proc.Name
		if procName == "" {
			procName = "unknown"
		}

		detail := map[string]interface{}{
			"remote_addr":  ip,
			"remote_port":  conn.RemotePort,
			"local_addr":   conn.LocalAddr,
			"local_port":   conn.LocalPort,
			"process_name": procName,
		}
		if proc.PID > 0 {
			detail["process_pid"] = proc.PID
		}

		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: fmt.Sprintf("network-new-outbound:%s", ip),
			Severity:  severity,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("new outbound connection to %s:%d (process: %s)", ip, conn.RemotePort, procName),
			Detail:    detail,
		})
	}

	return findings, nil
}

// Rebaseline snapshots the current set of public remote IPs as known-good.
// This should be called after deploying new services, adding integrations,
// or any planned change that introduces new outbound connections.
func (m *Module) Rebaseline(ctx context.Context) error {
	conns, err := m.scanConnections()
	if err != nil {
		return err
	}

	m.baseline = NetworkBaseline{
		KnownRemoteIPs: make(map[string]bool),
		Initialized:    true,
	}
	for _, c := range conns {
		if !isPrivateIP(c.RemoteAddr) {
			m.baseline.KnownRemoteIPs[c.RemoteAddr] = true
		}
	}
	m.baselineLoaded = true
	return m.store.Save(m.Name(), m.baseline)
}

// scanConnections reads both IPv4 and IPv6 TCP connection tables and returns
// all ESTABLISHED connections. Both files are attempted independently so that
// failure to read one (e.g., IPv6 disabled) does not prevent reading the other.
func (m *Module) scanConnections() ([]Connection, error) {
	var conns []Connection
	for _, path := range []string{m.ProcTCP, m.ProcTCP6} {
		entries, err := parseEstablished(path)
		if err != nil {
			continue // file might not exist (e.g., IPv6 disabled in kernel)
		}
		conns = append(conns, entries...)
	}
	return conns, nil
}

// parseEstablished reads a /proc/net/tcp-style file and returns ESTABLISHED
// connections. The /proc/net/tcp format is documented in proc(5) and has
// this columnar layout:
//
//	sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt ...
//	0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 ...
//
// We only care about columns 1 (local addr), 2 (remote addr), and 3 (state).
// State "01" is ESTABLISHED — active connections with completed handshake.
// We ignore LISTEN (0A), TIME_WAIT (06), etc. because they don't represent
// active outbound communication.
func parseEstablished(path string) ([]Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var conns []Connection
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip the header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// State field is at index 3, hex-encoded. "01" = TCP_ESTABLISHED.
		// This is defined in include/net/tcp_states.h in the kernel source.
		if fields[3] != "01" {
			continue
		}

		// Fields[1] = local address:port in hex, fields[2] = remote address:port
		localAddr, localPort, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}

		conns = append(conns, Connection{
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      "ESTABLISHED",
			Inode:      fields[9],
		})
	}

	return conns, scanner.Err()
}

// parseHexAddr parses a hex-encoded "address:port" string from /proc/net/tcp.
// Example: "0100007F:0035" -> ("127.0.0.1", 53)
// The address portion is hex-encoded IP bytes; the port is a 4-digit hex number.
func parseHexAddr(s string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address: %s", s)
	}

	var port int
	_, err := fmt.Sscanf(parts[1], "%x", &port)
	if err != nil {
		return "", 0, err
	}

	addr, err := hexToIP(parts[0])
	if err != nil {
		return "", 0, err
	}

	return addr, port, nil
}

// hexToIP converts a hex-encoded IP address from /proc/net/tcp format to a
// human-readable string. The kernel stores addresses in little-endian byte
// order within each 4-byte group, which is why we reverse the byte order
// during conversion. IPv4 addresses are 4 bytes (8 hex chars) and IPv6
// addresses are 16 bytes (32 hex chars) with each 4-byte group independently
// little-endian.
func hexToIP(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}

	switch len(b) {
	case 4:
		// IPv4 — reverse bytes because kernel stores in little-endian
		// (network byte order is big-endian, but /proc/net/tcp uses host
		// byte order which is little-endian on x86/ARM)
		return net.IPv4(b[3], b[2], b[1], b[0]).String(), nil
	case 16:
		// IPv6 — each 4-byte group is independently stored in little-endian.
		// We reverse within each group but not the group order.
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				ip[i*4+j] = b[i*4+3-j]
			}
		}
		return ip.String(), nil
	default:
		return "", fmt.Errorf("unexpected address length: %d", len(b))
	}
}

// isPrivateIP returns true if the IP is loopback, private (RFC1918), link-local,
// or unspecified. These addresses are filtered out because connections to them
// are internal traffic that is expected to vary and would generate excessive
// noise if included in baseline comparison. We only care about connections to
// public internet IPs, which indicate external communication.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 127.0.0.0/8 or ::1 — local machine traffic, always expected
	if ip.IsLoopback() {
		return true
	}

	// 169.254.0.0/16 or fe80::/10 — link-local, used for DHCP/mDNS/etc.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// 0.0.0.0 or :: — unspecified address, appears in LISTEN state entries
	if ip.IsUnspecified() {
		return true
	}

	// RFC1918 private ranges and IPv6 unique local addresses.
	// These represent internal network traffic that should not trigger alerts.
	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},     // Class A private (large enterprises, cloud VPCs)
		{"172.16.0.0/12"},  // Class B private (medium networks)
		{"192.168.0.0/16"}, // Class C private (home/small office networks)
		{"fc00::/7"},       // IPv6 Unique Local Address (ULA), RFC4193
	}

	for _, r := range privateRanges {
		_, cidr, err := net.ParseCIDR(r.network)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}
