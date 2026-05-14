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

## Module Routing

- Markdown routing lives in `specs/MODULES.md`
- Service boundaries live in `specs/agent.md` and `specs/mgr.md`
- API routes live in `specs/agent-api.md` and `specs/mgr-api.md`
- Resource contracts live in `specs/agent/` and `specs/mgr/`
- Architecture notes live in `docs/architecture/`

Keep `AGENTS.md` as workflow guidance. Do not duplicate product contracts here.

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

- When behavior, API, fields, or semantics change, update the matching spec
- Use `specs/MODULES.md` to find the spec file
- Do not put product contracts in `AGENTS.md`

## Skill Routing

- File-backed plans and task routing: `skills/plan-workflow`
- Multi-step refactors and module splits: `skills/refactor-workflow`
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

For multi-step refactors, restore `.agent/` context, inspect matching `specs/` and `docs/architecture/`, write a source-backed plan, and wait for human confirmation before coding.
