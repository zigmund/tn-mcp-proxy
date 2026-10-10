# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## Build & Test

Go module `github.com/zigmund/tn-mcp-proxy`; the only dependency is `gopkg.in/yaml.v3`.

```bash
make build            # bin/tn-mcp-proxy, version from git describe
make test             # go test -race ./... (fuzz seed corpora run as normal tests)
make vet              # go vet ./...
make lint             # golangci-lint, falls back to go vet when not installed
make fmt              # gofmt -w .
make test-scripts     # scripts/next-version_test.sh (release version logic)
make fuzz FUZZTIME=30s  # every FuzzXxx target in turn
go build -o /dev/null ./...   # compile check without producing a binary
```

Before handing off: `gofmt -l .` is empty, and `go build`, `go vet ./...`,
`go test -race ./...` and `make lint` pass. Releases are cut by the manual
GitHub Actions workflow (see `docs/releasing.md`).

## Architecture Overview

One binary (`cmd/tn-mcp-proxy`) is an OAuth 2.1 authorization server plus a
reverse proxy for header-authenticated MCP upstreams. It is stateless: client
ids, codes, access and refresh tokens are AES-256-GCM sealed blobs carrying the
upstream credentials; the only state is bounded in-memory caches (single-use
codes and refresh families, rate limiters, re-check verdicts). Single instance
by design.

- `internal/config`: strict YAML loading, defaults, validation, limit constants
- `internal/seal`, `internal/tokens`: token encryption and payload types
- `internal/oauth`: metadata, DCR, authorize form, token endpoint, OAuth rate limits
- `internal/proxy`: per-upstream reverse proxy, `forbidden_arguments`
  inspection, tool-error re-check, proxy limits
- `internal/credcheck`: the `validate` MCP session (authorize form and re-check)
- `internal/server`: handler tree, timeouts, HSTS, signals; `internal/certreload`:
  TLS hot reload; `internal/httplog`: client IP and access log;
  `internal/ratelimit`: buckets and concurrency slots; `internal/logging`: slog

User docs live in `README.md` (quick start and pointers) and `docs/`
(`configuration.md` for every key and limit, `architecture.md` for behavior,
`releasing.md`). `docs/security/` holds published security reports: do not edit them.

## Conventions & Patterns

- Fail closed: anything not clearly accepted is refused (credential checks,
  body inspection, full single-use caches).
- Never log or echo secrets: no tokens, credential values, query strings or
  request bodies; config errors name field paths, not values.
- Config changes touch four places together: the struct and its doc comment in
  `internal/config`, `docs/configuration.md`, `deploy/config.example.yaml`
  (`TestExampleConfig` loads it) and, if user-visible, `README.md`. Keep the
  README short and link to `docs/`.
- Public repo: placeholders only (`mcp.example.com`, `REPLACE_ME`-style values),
  no real keys, hosts, IPs or personal data. Do not mention security-report
  finding ids outside `docs/security/`.
- Tests are hermetic (`httptest` servers, fake MCP upstream in
  `internal/oauth/mcpfake_test.go`, injectable clocks); table-driven where
  natural, run with `-race`. Add a fuzz target for new parsers of untrusted input.
- Handlers are mounted by exact pattern; time-bound or size-bound everything that
  reads client input, except the proxied MCP paths, which may stream (SSE).
