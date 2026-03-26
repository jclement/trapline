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

type Container struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

type ContainerBaseline struct {
	Containers map[string]string `json:"containers"` // name -> image
}

type Module struct {
	store      *baseline.Store
	baseline   ContainerBaseline
	socketPath string
	client     *http.Client
}

func New() *Module {
	return &Module{
		socketPath: "/var/run/docker.sock",
	}
}

func (m *Module) Name() string { return "containers" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.baseline = ContainerBaseline{Containers: make(map[string]string)}
	m.store.Load(m.Name(), &m.baseline)

	m.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", m.socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}

	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	containers, err := m.listContainers(ctx)
	if err != nil {
		return nil, nil // Docker may not be running
	}

	current := make(map[string]string)
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}
		if name == "" {
			name = c.ID[:12]
		}
		current[name] = c.Image
	}

	if len(m.baseline.Containers) == 0 {
		m.baseline.Containers = current
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding

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
