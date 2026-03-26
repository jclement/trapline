// Package ports implements a network port monitoring scanner for Trapline.
//
// # What It Monitors and Why
//
// This module tracks all listening TCP and UDP sockets on the system by reading
// directly from /proc/net/tcp, /proc/net/tcp6, /proc/net/udp, and /proc/net/udp6.
// Network listeners are a primary indicator of compromise: backdoors, C2 channels,
// and unauthorized services all require binding to a port. Detecting new or missing
// listeners is one of the fastest ways to identify active intrusions.
//
// # How It Works
//
// Instead of shelling out to netstat or ss, the module reads the kernel's
// /proc/net/* pseudo-files directly. This is both faster (no process spawn overhead)
// and harder for userspace rootkits to evade -- a rootkit that hooks libc or
// replaces netstat/ss binaries cannot hide ports from direct /proc reads (though
// a kernel rootkit still could).
//
// The /proc/net/tcp format encodes addresses and ports as hex strings in a
// host-byte-order (little-endian on x86) layout. The parser decodes these into
// human-readable IP:port tuples. For TCP sockets, only entries in state 0x0A
// (LISTEN) are included; UDP sockets are included regardless of state since UDP
// is connectionless.
//
// On first run, the module enters "learning mode" -- it records all current
// listeners as the baseline and produces no findings. Subsequent scans compare
// against this baseline and report deviations.
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - Command and Control (T1071): Unexpected listening port indicating a C2
//     implant or reverse shell listener.
//   - Persistence (T1543): New service binding to a port (e.g., a backdoor SSH
//     daemon on a non-standard port).
//   - Execution (T1059): Cryptominer or other malware binding to a port for pool
//     communication or management interfaces.
//   - Impact / Service Disruption: Expected service no longer listening, which
//     could indicate a DoS attack, service crash, or attacker stopping a service
//     to replace it.
//
// # What It Does NOT Catch (Known Limitations)
//
//   - Outbound-only connections: This module only monitors listeners, not outbound
//     connections. A reverse shell that connects out will not be detected here
//     (use the processes module for that).
//   - Ephemeral listeners: A service that binds, accepts one connection, and closes
//     may be missed between scan intervals.
//   - Kernel rootkits: A rootkit that hooks /proc/net/* at the kernel level can
//     hide entries from this module.
//   - Port reuse: An attacker replacing the legitimate process on an existing port
//     will not trigger an alert (same proto:addr:port key). The processes module
//     should catch this.
//   - Raw sockets and ICMP tunnels: Only TCP/UDP listeners are monitored.
//
// # False Positive Risks
//
//   - Legitimate service restarts on different ports (e.g., dynamic RPC ports).
//   - Container orchestration creating/destroying listeners.
//   - Development environments with frequently changing services.
//   - Mitigation: Rebaseline after planned infrastructure changes.
//
// # Performance Characteristics
//
//   - I/O: Four sequential file reads from /proc/net/* (virtual filesystem, very fast).
//     No disk I/O -- these are kernel-generated pseudo-files served from memory.
//   - CPU: Minimal. Parsing hex strings and comparing maps of typically dozens of
//     entries.
//   - Memory: Proportional to the number of listening sockets (typically tens to low
//     hundreds of entries).
//   - No external process spawns, no privilege requirements beyond read access to /proc.
//
// # Configuration Options
//
//   - Currently no user-configurable settings. The module monitors all listening
//     TCP/TCP6/UDP/UDP6 sockets.
//   - ProcTCP, ProcTCP6, ProcUDP, ProcUDP6 fields can be overridden for testing.
package ports

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// PortEntry represents a single listening socket identified by protocol, bind
// address, and port number. PID and Process are optional enrichment fields
// (currently not populated by the /proc/net parser, reserved for future use).
type PortEntry struct {
	Proto   string `json:"proto"`
	Address string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

// Module is the port monitoring scanner. It reads kernel socket tables directly
// from /proc/net/* to avoid dependency on userspace tools that rootkits can subvert.
type Module struct {
	store          *baseline.Store
	baseline       []PortEntry
	baselineLoaded bool
	// ProcTCP/ProcTCP6/ProcUDP/ProcUDP6: paths to /proc/net pseudo-files.
	// Exported for testing so unit tests can point at fixture files instead
	// of the real /proc filesystem.
	ProcTCP  string
	ProcTCP6 string
	ProcUDP  string
	ProcUDP6 string
}

// New creates a Module with default /proc/net paths. Call Init() before use.
func New() *Module {
	return &Module{
		ProcTCP:  "/proc/net/tcp",
		ProcTCP6: "/proc/net/tcp6",
		ProcUDP:  "/proc/net/udp",
		ProcUDP6: "/proc/net/udp6",
	}
}

// Name returns the module identifier used for baseline storage and finding IDs.
func (m *Module) Name() string { return "ports" }

// Init sets up the baseline store and loads any persisted baseline from disk.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)
	return nil
}

// Scan reads the current listening sockets and compares them against the baseline.
// New listeners are reported as SeverityHigh (potential backdoors/C2). Missing
// listeners are reported as SeverityMedium (potential service disruption).
// On the first run (no baseline), all current listeners are recorded as the
// baseline and no findings are returned.
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.scanPorts()
	if err != nil {
		return nil, err
	}

	// Learning mode: first scan establishes the baseline of expected listeners.
	// No findings are generated because we have no reference to compare against.
	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		_ = m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding
	baseMap := portsToMap(m.baseline)
	curMap := portsToMap(current)

	// Detect new listeners not present in the baseline. These are high severity
	// because a new listener often indicates a backdoor, C2 channel, or
	// unauthorized service.
	for key, cur := range curMap {
		if _, ok := baseMap[key]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: fmt.Sprintf("port-new:%s:%d", cur.Proto, cur.Port),
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new listening port %s/%d (%s)", cur.Proto, cur.Port, cur.Address),
				Detail: map[string]interface{}{
					"proto":   cur.Proto,
					"address": cur.Address,
					"port":    cur.Port,
					"process": cur.Process,
				},
			})
		}
	}

	// Detect missing listeners that were present in the baseline. These are
	// medium severity -- a missing expected service could indicate a crash,
	// DoS, or an attacker stopping a service to replace it with their own.
	for key, base := range baseMap {
		if _, ok := curMap[key]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: fmt.Sprintf("port-gone:%s:%d", base.Proto, base.Port),
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("expected port %s/%d no longer listening", base.Proto, base.Port),
				Detail: map[string]interface{}{
					"proto":   base.Proto,
					"address": base.Address,
					"port":    base.Port,
				},
			})
		}
	}

	return findings, nil
}

// Rebaseline captures the current set of listening ports as the new baseline.
// Call this after planned infrastructure changes to prevent false positives.
func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.scanPorts()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

// scanPorts reads all four /proc/net/* files (TCP, TCP6, UDP, UDP6) and
// aggregates the listening entries. Errors on individual files are silently
// ignored because some may not exist (e.g., IPv6 disabled).
func (m *Module) scanPorts() ([]PortEntry, error) {
	var ports []PortEntry

	for _, spec := range []struct {
		path  string
		proto string
	}{
		{m.ProcTCP, "tcp"},
		{m.ProcTCP6, "tcp6"},
		{m.ProcUDP, "udp"},
		{m.ProcUDP6, "udp6"},
	} {
		entries, err := parseProcNet(spec.path, spec.proto)
		if err != nil {
			continue // file might not exist (e.g., IPv6 disabled)
		}
		ports = append(ports, entries...)
	}

	return ports, nil
}

// parseProcNet reads a /proc/net/tcp-style file and returns listening entries.
// The file format is documented in the Linux kernel source (net/ipv4/tcp_ipv4.c):
//
//	sl  local_address rem_address   st tx_queue rx_queue ...
//	0:  0100007F:0035 00000000:0000 0A ...
//
// Fields[1] is the local address:port in hex, fields[3] is the socket state.
// For TCP, state 0x0A means LISTEN. UDP sockets are connectionless, so all
// entries are included regardless of state.
func parseProcNet(path, proto string) ([]PortEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var entries []PortEntry
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip the header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		// Filter by socket state: 0x0A = TCP_LISTEN.
		// For UDP, there is no "listen" state, so we include all entries.
		// This means we see all bound UDP sockets, which is the correct
		// behavior since any bound UDP socket can receive traffic.
		state := fields[3]
		if proto == "tcp" || proto == "tcp6" {
			if state != "0A" {
				continue
			}
		}

		// fields[1] is "local_address:port" in hex encoding
		addr, port, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		entries = append(entries, PortEntry{
			Proto:   proto,
			Address: addr,
			Port:    port,
		})
	}

	return entries, scanner.Err()
}

// parseHexAddr splits a hex-encoded "address:port" string from /proc/net/tcp
// into a human-readable IP string and integer port number.
// Example input: "0100007F:0035" -> ("127.0.0.1", 53, nil)
func parseHexAddr(s string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address: %s", s)
	}

	// Port is a straightforward hex-to-int conversion
	portHex := parts[1]
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, err
	}

	// Address requires byte-order reversal (see hexToIP)
	addrHex := parts[0]
	addr, err := hexToIP(addrHex)
	if err != nil {
		return "", 0, err
	}

	return addr, int(port), nil
}

// hexToIP converts a hex-encoded IP address from /proc/net format to a
// human-readable string. The kernel stores addresses in host byte order
// (little-endian on x86), so each 4-byte group must be reversed.
//
// For IPv4 (4 bytes): "0100007F" -> reverse bytes -> 127.0.0.1
// For IPv6 (16 bytes): each 4-byte word is individually byte-reversed,
// which matches the kernel's storage of IPv6 addresses as four 32-bit
// words in host byte order.
func hexToIP(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}

	switch len(b) {
	case 4:
		// IPv4: stored as a single 32-bit value in little-endian (on x86).
		// Bytes must be reversed to get network byte order for display.
		return net.IPv4(b[3], b[2], b[1], b[0]).String(), nil
	case 16:
		// IPv6: stored as four 32-bit words, each in little-endian.
		// We reverse each 4-byte group independently to reconstruct the
		// standard big-endian (network byte order) representation.
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

// portsToMap converts a slice of PortEntry into a map keyed by
// "proto:address:port" for efficient set-difference operations during
// baseline comparison.
func portsToMap(ports []PortEntry) map[string]PortEntry {
	m := make(map[string]PortEntry)
	for _, p := range ports {
		key := fmt.Sprintf("%s:%s:%d", p.Proto, p.Address, p.Port)
		m[key] = p
	}
	return m
}
