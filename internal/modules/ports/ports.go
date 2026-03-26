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

type PortEntry struct {
	Proto   string `json:"proto"`
	Address string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

type Module struct {
	store          *baseline.Store
	baseline       []PortEntry
	baselineLoaded bool
	// For testing: override the proc paths
	ProcTCP  string
	ProcTCP6 string
	ProcUDP  string
	ProcUDP6 string
}

func New() *Module {
	return &Module{
		ProcTCP:  "/proc/net/tcp",
		ProcTCP6: "/proc/net/tcp6",
		ProcUDP:  "/proc/net/udp",
		ProcUDP6: "/proc/net/udp6",
	}
}

func (m *Module) Name() string { return "ports" }

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
	current, err := m.scanPorts()
	if err != nil {
		return nil, err
	}

	if !m.baselineLoaded {
		m.baseline = current
		m.baselineLoaded = true
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding
	baseMap := portsToMap(m.baseline)
	curMap := portsToMap(current)

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

func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.scanPorts()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

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
			continue // file might not exist
		}
		ports = append(ports, entries...)
	}

	return ports, nil
}

// parseProcNet reads a /proc/net/tcp-style file and returns listening entries.
func parseProcNet(path, proto string) ([]PortEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []PortEntry
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		// State: 0A = LISTEN for TCP
		state := fields[3]
		if proto == "tcp" || proto == "tcp6" {
			if state != "0A" {
				continue
			}
		}

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

// parseHexAddr parses a hex-encoded address:port from /proc/net/tcp.
func parseHexAddr(s string) (string, int, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address: %s", s)
	}

	portHex := parts[1]
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return "", 0, err
	}

	addrHex := parts[0]
	addr, err := hexToIP(addrHex)
	if err != nil {
		return "", 0, err
	}

	return addr, int(port), nil
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
		// IPv6
		ip := make(net.IP, 16)
		// Each 4-byte group is little-endian
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

func portsToMap(ports []PortEntry) map[string]PortEntry {
	m := make(map[string]PortEntry)
	for _, p := range ports {
		key := fmt.Sprintf("%s:%s:%d", p.Proto, p.Address, p.Port)
		m[key] = p
	}
	return m
}
