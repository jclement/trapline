// Package containers implements Docker container monitoring to detect rogue
// containers, unexpected image changes, and missing expected services by
// communicating directly with the Docker daemon over its Unix socket API.
//
// # What It Monitors and Why
//
// Containers are a common attack vector: compromised hosts may have
// cryptominer containers deployed, attackers may spin up reverse shell
// containers for persistence, or legitimate containers may be replaced with
// trojaned images. This module baselines the expected set of running
// containers (by name and image) and alerts on deviations.
//
// # How It Works
//
//  1. Queries the Docker Engine API (/containers/json) over the Unix socket
//     at /var/run/docker.sock using a standard HTTP client configured with
//     a Unix domain socket transport.
//  2. Builds a map of container name -> image from the API response.
//  3. On first scan, stores this map as the baseline (learning mode).
//  4. On subsequent scans, compares current containers against baseline:
//     - Containers present now but not in baseline -> "unexpected container"
//     (SeverityHigh: possible rogue container / cryptominer / reverse shell)
//     - Containers in baseline but not running now -> "missing container"
//     (SeverityMedium: expected service may have been stopped or crashed)
//
// The module communicates via the Docker socket API rather than shelling out
// to the `docker` CLI. This is both more reliable (no PATH dependency, no
// shell injection risk) and harder for an attacker to intercept via PATH
// manipulation (MITRE T1574.007).
//
// # What It Catches (MITRE ATT&CK Mappings)
//
//   - T1610 (Deploy Container): rogue containers spun up by attacker
//   - T1496 (Resource Hijacking): cryptominer containers
//   - T1053 (Scheduled Task/Job): containers used for persistence
//   - T1543 (Create or Modify System Process): unexpected service containers
//   - T1489 (Service Stop): detection of expected containers going missing
//
// # Known Limitations and Blind Spots
//
//   - Only monitors Docker; Podman, containerd (without Docker shim), and
//     other container runtimes are not supported.
//   - Does not detect image tampering if the image tag/name is unchanged
//     (e.g., attacker pushes a malicious image with the same tag). Would
//     need image digest comparison to catch this.
//   - If Docker is not running or the socket is inaccessible, the module
//     silently returns no findings rather than alerting.
//   - Does not inspect container configuration (mounts, capabilities,
//     network mode, privileged flag) — a container could be reconfigured
//     dangerously while keeping the same name and image.
//   - Stopped/exited containers are not listed by the default API query
//     (only running containers), so a container that was stopped and
//     restarted between scans may not be caught.
//   - Container name collisions: if an attacker removes a legitimate
//     container and replaces it with a different image under the same name,
//     the current implementation does not detect the image change (it only
//     checks name presence, not name-to-image mapping for existing entries).
//
// # False Positive Risks
//
//   - Auto-scaling orchestrators (Docker Swarm, Kubernetes via Docker) may
//     create and destroy containers frequently. This module is best suited
//     for hosts with a relatively stable container set.
//   - Container restarts with new names (e.g., random suffixes from
//     docker-compose --scale) will trigger unexpected-container alerts.
//   - Routine maintenance (image updates, container recreation) requires
//     rebaselining to avoid persistent alerts.
//
// # Performance Characteristics
//
// Single HTTP request to the local Docker daemon over Unix socket. Response
// size is proportional to the number of running containers. Typical latency
// is under 50ms. The 10-second timeout prevents the scan from hanging if
// the Docker daemon is unresponsive.
//
// # Configuration Options
//
//   - socketPath (string, default "/var/run/docker.sock"): path to the Docker
//     Engine API Unix socket. Not currently exposed in config but can be
//     overridden programmatically for testing.
package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

// Container represents the subset of Docker container metadata returned by
// the /containers/json API endpoint that we need for baseline comparison.
type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"` // Docker prefixes names with "/"; we strip it
	Image  string            `json:"Image"` // Image name (may include tag)
	State  string            `json:"State"` // "running", "exited", etc.
	Labels map[string]string `json:"Labels"`
}

// ContainerBaseline maps container names to their expected images.
// This allows detection of both unexpected containers and missing ones.
type ContainerBaseline struct {
	Containers map[string]string `json:"containers"` // name -> image
}

// Module monitors Docker containers via the Docker Engine API Unix socket.
// It baselines the set of running containers and alerts on deviations.
type Module struct {
	store          *baseline.Store
	baseline       ContainerBaseline
	baselineLoaded bool
	socketPath     string       // Path to the Docker daemon Unix socket
	client         *http.Client // HTTP client configured to talk over the Unix socket
}

// New creates a new container monitoring module with the default Docker socket
// path. The HTTP client is initialized in Init() to allow the baseline store
// to be configured first.
func New() *Module {
	return &Module{
		socketPath: "/var/run/docker.sock",
	}
}

func (m *Module) Name() string { return "containers" }

// Init sets up the baseline store and configures an HTTP client that speaks
// to the Docker daemon over its Unix socket. Using Unix sockets instead of
// TCP avoids exposing the Docker API to the network and is the standard
// communication method for local Docker interactions.
func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baseline = ContainerBaseline{Containers: make(map[string]string)}
	m.baselineLoaded, _ = m.store.Load(m.Name(), &m.baseline)

	// Configure an HTTP client that dials the Docker Unix socket instead of
	// a TCP address. The "http://localhost" URL is required by the HTTP spec
	// but the actual connection goes through the Unix socket. This approach
	// is more reliable than shelling out to `docker` CLI because:
	// (a) it avoids PATH manipulation attacks (MITRE T1574.007),
	// (b) it works even if docker CLI is not installed (e.g., containerd-only),
	// (c) it avoids shell injection risks from container names/images.
	m.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", m.socketPath)
			},
		},
		// 10-second timeout prevents the scan from hanging indefinitely if
		// the Docker daemon is unresponsive (e.g., deadlocked, overloaded).
		Timeout: 10 * time.Second,
	}

	return nil
}

// Scan queries the Docker daemon for running containers, builds a name->image
// map, and compares it against the baseline. Two types of deviations are detected:
//   - Unexpected containers: present now but not in baseline (possible rogue
//     container — cryptominer, reverse shell, attacker tooling)
//   - Missing containers: in baseline but not running now (possible service
//     disruption — attacker stopped a service, or it crashed)
func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	containers, err := m.listContainers(ctx)
	if err != nil {
		// Docker may not be running, or the socket may not be accessible.
		// This is not an error condition — the host may simply not use Docker.
		// Return no findings silently rather than failing the entire scan.
		return nil, nil
	}

	// Build a name->image map from the current Docker state.
	current := make(map[string]string)
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
			// Docker API prefixes container names with "/" (a legacy
			// artifact from multi-host networking). Strip it for cleaner
			// baseline keys and human-readable finding summaries.
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}
		// Fall back to truncated container ID if no name is assigned.
		// 12 characters matches the `docker ps` default display.
		if name == "" {
			name = c.ID[:12]
		}
		current[name] = c.Image
	}

	// Learning mode: first scan records all running containers as expected.
	// This assumes the system is in a known-good state at deployment time.
	if !m.baselineLoaded {
		m.baseline.Containers = current
		m.baselineLoaded = true
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding

	// Check for unexpected containers (present now but not in baseline).
	// SeverityHigh because rogue containers are a strong indicator of
	// compromise — attackers deploy cryptominers, C2 relays, and reverse
	// shells as containers for easy cleanup and isolation from the host.
	for name, image := range current {
		if _, ok := m.baseline.Containers[name]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "container-unexpected:" + name,
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("unexpected container '%s' running (image: %s)", name, image),
				Detail:    map[string]interface{}{"name": name, "image": image},
			})
		}
	}

	// Check for missing containers (in baseline but not currently running).
	// SeverityMedium because this could indicate an attacker stopped a
	// security-relevant service, or it could just be a normal container
	// restart/crash that will auto-recover.
	for name := range m.baseline.Containers {
		if _, ok := current[name]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "container-missing:" + name,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("expected container '%s' not running", name),
				Detail:    map[string]interface{}{"name": name},
			})
		}
	}

	return findings, nil
}

// Rebaseline captures the current set of running containers as the new
// expected state. Call this after deploying new containers, removing old ones,
// or performing any planned infrastructure change to avoid false positives.
func (m *Module) Rebaseline(ctx context.Context) error {
	containers, err := m.listContainers(ctx)
	if err != nil {
		return err
	}

	m.baseline.Containers = make(map[string]string)
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
			// Strip the leading "/" that Docker API adds to container names
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}
		if name == "" {
			name = c.ID[:12]
		}
		m.baseline.Containers[name] = c.Image
	}

	return m.store.Save(m.Name(), m.baseline)
}

// listContainers queries the Docker Engine API for all running containers.
// The URL "http://localhost/containers/json" is routed through the Unix socket
// transport configured in Init() — the "localhost" hostname is ignored by the
// dialer. The /containers/json endpoint returns only running containers by
// default (equivalent to `docker ps` without --all), which is what we want
// since stopped containers are not a security concern for this module.
func (m *Module) listContainers(ctx context.Context) ([]Container, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/containers/json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var containers []Container
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, err
	}
	return containers, nil
}
