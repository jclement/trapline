# Trapline

Host integrity monitoring daemon for Linux. Go project at `github.com/jclement/tripline`.

## Build & Test

```bash
# Requires: go 1.25+, CGO_ENABLED=0 (static binary, no CGO)
export PATH=/usr/local/go/bin:$PATH GOROOT=/usr/local/go

CGO_ENABLED=0 go build -o trapline ./cmd/trapline    # build
CGO_ENABLED=0 go test ./...                           # unit tests (166 tests, 21 packages)
CGO_ENABLED=0 go vet ./...                            # vet
CGO_ENABLED=0 go test -tags e2e -v ./e2e/ -timeout 5m # e2e tests (requires Docker)
```

## Architecture

- `cmd/trapline/` - CLI entrypoint (all commands)
- `internal/engine/` - module scheduler, dedup, enrichment
- `internal/modules/` - 13 scanner modules (each implements `engine.Module` interface)
- `internal/config/` - YAML config loader
- `internal/baseline/` - JSON-on-disk baseline store
- `internal/store/` - SQLite findings + ignore database
- `internal/output/` - output sinks (console, file, TCP, webhook)
- `internal/tui/` - pretty terminal output (lipgloss)
- `internal/taglines/` - 200 taglines (shown in CLI banners)
- `internal/updater/` - self-update from GitHub releases
- `internal/install/` - install, uninstall, doctor
- `pkg/finding/` - shared Finding type
- `e2e/` - Docker-based end-to-end tests

## Key patterns

- All modules implement `engine.Module` interface: `Name()`, `Init()`, `Scan()`, `Rebaseline()`
- Modules use `baseline.Store` for JSON persistence, `store.Store` for SQLite
- All /proc and /sys paths are struct fields on modules for testability
- Tests use `t.TempDir()` and inject fake filesystem paths
- `CGO_ENABLED=0` is required everywhere (pure Go SQLite via modernc.org/sqlite)
