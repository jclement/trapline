package users

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jclement/tripline/internal/baseline"
	"github.com/jclement/tripline/internal/engine"
	"github.com/jclement/tripline/pkg/finding"
)

type UserEntry struct {
	Name  string `json:"name"`
	UID   string `json:"uid"`
	GID   string `json:"gid"`
	Shell string `json:"shell"`
	Home  string `json:"home"`
}

type GroupEntry struct {
	Name    string   `json:"name"`
	GID     string   `json:"gid"`
	Members []string `json:"members"`
}

type UsersBaseline struct {
	Users       []UserEntry  `json:"users"`
	Groups      []GroupEntry `json:"groups"`
	SudoersHash string       `json:"sudoers_hash"`
}

type Module struct {
	store    *baseline.Store
	baseline UsersBaseline
	// For testing
	PasswdPath  string
	GroupPath   string
	SudoersPath string
}

func New() *Module {
	return &Module{
		PasswdPath:  "/etc/passwd",
		GroupPath:   "/etc/group",
		SudoersPath: "/etc/sudoers",
	}
}

func (m *Module) Name() string { return "users" }

func (m *Module) Init(cfg engine.ModuleConfig) error {
	store, err := baseline.NewStore(cfg.BaselinesDir)
	if err != nil {
		return err
	}
	m.store = store
	m.store.Load(m.Name(), &m.baseline)
	return nil
}

func (m *Module) Scan(ctx context.Context) ([]finding.Finding, error) {
	current, err := m.snapshot()
	if err != nil {
		return nil, err
	}

	if len(m.baseline.Users) == 0 {
		m.baseline = current
		m.store.Save(m.Name(), m.baseline)
		return nil, nil
	}

	var findings []finding.Finding

	// Check users
	baseUsers := usersToMap(m.baseline.Users)
	curUsers := usersToMap(current.Users)

	for name, cur := range curUsers {
		if base, ok := baseUsers[name]; ok {
			if cur.UID != base.UID {
				sev := finding.SeverityCritical
				if cur.UID == "0" {
					sev = finding.SeverityCritical
				}
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "user-uid-changed:" + name,
					Severity:  sev,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("user '%s' UID changed from %s to %s", name, base.UID, cur.UID),
					Detail:    map[string]interface{}{"user": name, "old_uid": base.UID, "new_uid": cur.UID},
				})
			}
			if cur.Shell != base.Shell {
				findings = append(findings, finding.Finding{
					Timestamp: time.Now().UTC(),
					FindingID: "user-shell-changed:" + name,
					Severity:  finding.SeverityMedium,
					Status:    finding.StatusNew,
					Summary:   fmt.Sprintf("user '%s' shell changed from %s to %s", name, base.Shell, cur.Shell),
					Detail:    map[string]interface{}{"user": name, "old_shell": base.Shell, "new_shell": cur.Shell},
				})
			}
		} else {
			sev := finding.SeverityHigh
			if cur.UID == "0" {
				sev = finding.SeverityCritical
			}
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "user-added:" + name,
				Severity:  sev,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new user '%s' added (UID %s)", name, cur.UID),
				Detail:    map[string]interface{}{"user": name, "uid": cur.UID, "shell": cur.Shell, "home": cur.Home},
			})
		}
	}

	for name := range baseUsers {
		if _, ok := curUsers[name]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "user-removed:" + name,
				Severity:  finding.SeverityHigh,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("user '%s' removed", name),
				Detail:    map[string]interface{}{"user": name},
			})
		}
	}

	// Check groups for new members
	baseGroups := groupsToMap(m.baseline.Groups)
	curGroups := groupsToMap(current.Groups)

	for name, cur := range curGroups {
		if _, ok := baseGroups[name]; !ok {
			findings = append(findings, finding.Finding{
				Timestamp: time.Now().UTC(),
				FindingID: "group-added:" + name,
				Severity:  finding.SeverityMedium,
				Status:    finding.StatusNew,
				Summary:   fmt.Sprintf("new group '%s' added", name),
				Detail:    map[string]interface{}{"group": name, "gid": cur.GID},
			})
		}
	}

	// Check sudoers
	if current.SudoersHash != m.baseline.SudoersHash && current.SudoersHash != "" {
		findings = append(findings, finding.Finding{
			Timestamp: time.Now().UTC(),
			FindingID: "sudoers-modified",
			Severity:  finding.SeverityHigh,
			Status:    finding.StatusNew,
			Summary:   "sudoers file modified",
			Detail:    map[string]interface{}{"baseline_hash": m.baseline.SudoersHash, "current_hash": current.SudoersHash},
		})
	}

	return findings, nil
}

func (m *Module) Rebaseline(ctx context.Context) error {
	current, err := m.snapshot()
	if err != nil {
		return err
	}
	m.baseline = current
	return m.store.Save(m.Name(), m.baseline)
}

func (m *Module) snapshot() (UsersBaseline, error) {
	users, err := parsePasswd(m.PasswdPath)
	if err != nil {
		return UsersBaseline{}, fmt.Errorf("reading passwd: %w", err)
	}

	groups, err := parseGroup(m.GroupPath)
	if err != nil {
		groups = nil // non-fatal
	}

	sudoersHash := hashFile(m.SudoersPath)

	return UsersBaseline{
		Users:       users,
		Groups:      groups,
		SudoersHash: sudoersHash,
	}, nil
}

func parsePasswd(path string) ([]UserEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var users []UserEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			continue
		}
		users = append(users, UserEntry{
			Name:  fields[0],
			UID:   fields[2],
			GID:   fields[3],
			Home:  fields[5],
			Shell: fields[6],
		})
	}
	return users, scanner.Err()
}

func parseGroup(path string) ([]GroupEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var groups []GroupEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		var members []string
		if fields[3] != "" {
			members = strings.Split(fields[3], ",")
		}
		groups = append(groups, GroupEntry{
			Name:    fields[0],
			GID:     fields[2],
			Members: members,
		})
	}
	return groups, scanner.Err()
}

func hashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func usersToMap(users []UserEntry) map[string]UserEntry {
	m := make(map[string]UserEntry)
	for _, u := range users {
		m[u.Name] = u
	}
	return m
}

func groupsToMap(groups []GroupEntry) map[string]GroupEntry {
	m := make(map[string]GroupEntry)
	for _, g := range groups {
		m[g.Name] = g
	}
	return m
}
