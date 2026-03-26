package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// Connection represents a parsed TCP connection from /proc/net/tcp.
type Connection struct {
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
}

// NetworkBaseline stores known-good remote IPs.
type NetworkBaseline struct {
	KnownRemoteIPs map[string]bool `json:"known_remote_ips"`
	Initialized    bool            `json:"initialized"`
}

// Module monitors established outbound connections.
type Module struct {
	store          *baseline.Store
	baseline       NetworkBaseline
	baselineLoaded bool
	// For testing: override the proc paths
	ProcTCP  string
	ProcTCP6 string
}

// New creates a new network module with default proc paths.
func New() *Module {
	return &Module{
		ProcTCP:  "/proc/net/tcp",
		ProcTCP6: "/proc/net/tcp6",
	}
}

func (m *Module) Name() string { return "network" }

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
	conns, err := m.scanConnections()
	if err != nil {
		return nil, err
	}

	// Extract unique public remote IPs
	currentIPs := make(map[string]Connection)
	for _, c := range conns {
		if !isPrivateIP(c.RemoteAddr) {
			if _, exists := currentIPs[c.RemoteAddr]; !exists {
				currentIPs[c.RemoteAddr] = c
			}
		}
	}

	// First scan: learn baseline
	if !m.baselineLoaded || !m.baseline.Initialized {
		m.baseline = NetworkBaseline{
			KnownRemoteIPs: make(map[string]bool),
			Initialized:    true,
		}
		for ip := range currentIPs {
			m.baseline.KnownRemoteIPs[ip] = true
		}
		m.baselineLoaded = true
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	// Detect new outbound IPs
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

	// Determine severity: multiple new IPs = critical (potential C2 burst)
	severity := finding.SeverityHigh
	if len(newIPs) > 1 {
		severity = finding.SeverityCritical
	}

	for _, ip := range newIPs {
		conn := currentIPs[ip]
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: fmt.Sprintf("network-new-outbound:%s", ip),
			Severity:  severity,
			Status:    finding.StatusNew,
			Summary:   fmt.Sprintf("new outbound connection to %s:%d", ip, conn.RemotePort),
			Detail: map[string]interface{}{
				"remote_addr": ip,
				"remote_port": conn.RemotePort,
				"local_addr":  conn.LocalAddr,
				"local_port":  conn.LocalPort,
			},
		})
	}

	return findings, nil
}

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

func (m *Module) scanConnections() ([]Connection, error) {
	var conns []Connection
	for _, path := range []string{m.ProcTCP, m.ProcTCP6} {
		entries, err := parseEstablished(path)
		if err != nil {
			continue // file might not exist
		}
		conns = append(conns, entries...)
	}
	return conns, nil
}

// parseEstablished reads a /proc/net/tcp-style file and returns ESTABLISHED connections.
func parseEstablished(path string) ([]Connection, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []Connection
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		// State 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}

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
		})
	}

	return conns, scanner.Err()
}

// parseHexAddr parses a hex-encoded address:port from /proc/net/tcp.
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

func hexToIP(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}

	switch len(b) {
	case 4:
		// IPv4 - stored in little-endian
		return net.IPv4(b[3], b[2], b[1], b[0]).String(), nil
	case 16:
		// IPv6 - each 4-byte group is little-endian
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

// isPrivateIP returns true if the IP is loopback, private (RFC1918), or link-local.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Loopback
	if ip.IsLoopback() {
		return true
	}

	// Link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Unspecified (0.0.0.0 or ::)
	if ip.IsUnspecified() {
		return true
	}

	// RFC1918 private ranges
	privateRanges := []struct {
		network string
	}{
		{"10.0.0.0/8"},
		{"172.16.0.0/12"},
		{"192.168.0.0/16"},
		{"fc00::/7"}, // IPv6 unique local
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
