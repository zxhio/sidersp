# AGENTS

Side-path analysis and active response platform for mirrored traffic.

Agent rules live here. Product contracts live in `specs/`. Technical docs live in `docs/`. Agent artifacts live in `.agent/`.

## Writing Style

- Keep descriptions short and precise.

## Repository Layout

- `cmd/`: entrypoints
- `internal/`: backend runtime modules
- `bpf/`: XDP/BPF programs
- `configs/`: config samples and defaults
- `deploy/`: deployment assets
- `docs/`: technical docs
- `specs/`: product contracts
- `web/`: management frontend
- `.github/`: repository automation and PR templates
- `skills/`: repo-local agent skills
- `.agent/`: local plans and reviews

## Module Boundaries

| Module | Responsibility |
|--------|----------------|
| `dataplane` | Data plane: XDP packet parsing, rule matching, kernel TX (`tcp_reset`), XSK redirect, event output |
| `controlplane` | Control plane: rule management, state maintenance, statistics aggregation, workflow orchestration |
| `analysis` | Planned deep analysis integration: analysis task submission and analysis result ingestion |
| `response` | Active user-space response execution: XSK metadata decode, packet build/TX, action execution, result feedback |
| `console` / `web` | Management plane: REST API, status display, statistics view, rule CRUD |

- Do not stack logic across module boundaries
- Do not put control logic in the data plane
- Do not put core pipeline logic in `console` / `web`
- Do not execute rule, analysis, or response decisions in the presentation layer
- When changing interfaces, events, rules, or response semantics, update the corresponding spec document

## Build & Test

- Backend build: `go build ./...`
- Backend test: `go test ./...`
- Frontend build: `npm --prefix web run build`
- Full build: `make build-all`
- Canonical unit test: `make test`
- BPF codegen: `go generate ./internal/dataplane`
- BPF kernel tests: `make test-bpf`

If a change touches `bpf/` or `internal/dataplane/`, prefer `make test`.
Do not edit `internal/dataplane/sidersp_bpfel.go` directly; regenerate it.

## Environment & Recovery

- Go version: `1.25.5`
- OS target: Linux
- BPF rebuild needs `clang` / LLVM
- Real dataplane / XDP / AF_XDP validation needs root or equivalent capabilities and a suitable NIC
- BPF kernel tests are gated by `SIDERSP_RUN_BPF_TESTS=1`
- If `go test ./...` fails because generated dataplane artifacts are stale, run `go generate ./internal/dataplane` or `make test`
- If `make test-bpf` fails due to host privilege or NIC limits, document it as an environment skip unless the task is specifically about kernel dataplane behavior

## Spec Sync

- Update the matching spec in the same change when you modify interfaces, events, rules, stats, or response semantics
- Keep BPF action constants, Go action codes, and specs aligned when changing dataplane actions
- `specs/MODULES.md`: module ownership and boundaries
- `specs/RULES.md`: rule schema, action params, compatibility
- `specs/EVENTS.md`: dataplane observation fields and verdict semantics
- `specs/RESPONSES.md`: response execution path, defaults, fallbacks
- `specs/STATS.md`: authoritative source for public metric names and meanings

## Skill Routing

- File-backed plan before coding: `skills/planning-with-files`
- AI change review: `skills/agent-review`
- Go structure and ownership: `skills/go-abstraction`
- Go style and test scope: `skills/go-coding-style`
- Go logging: `skills/go-logging`
- Gin REST API changes: `skills/go-rest-api`
- Frontend changes under `web/`: `skills/web-console`
- Git staging and commits: `skills/git-workflow`

Use the smallest skill set that fits the task. If you change agent workflow, update the matching file in `AGENTS.md` or `skills/`.

## Coding References

- Go structure: `skills/go-abstraction`
- Go style and test scope: `skills/go-coding-style`
- Logging: `skills/go-logging`

## Agent Workspace

- `.agent/plans/`: local plan files
- `.agent/reviews/`: local review notes
- `.agent/templates/`: plan and review templates
- Local gate: `make ai-review`
- PR carrier: `.github/pull_request_template.md` under `## AI Review`
- Do not put AI workflow rules in `docs/` or `specs/`
