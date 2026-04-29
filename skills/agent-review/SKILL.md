---
name: agent-review
description: Review AI-authored changes against requested scope, project rules, matching specs, and verification requirements before handoff.
---

## When to use this

Use when reviewing AI-authored changes before handoff, commit, or merge.

## Goal

Check four things:

- scope
- spec sync
- area rules
- verification

## Review inputs

Inspect only what you need:

- the request, plan, or stated scope
- the current diff or changed files
- `AGENTS.md`
- matching files in `specs/`, `docs/`, `cmd/`, `internal/`, `bpf/`, `web/`, or `skills/`

## Review checklist

### Scope

- [ ] The change stays within the requested scope.
- [ ] No unrelated features or refactors were introduced.
- [ ] Public concepts were not renamed without a reason.
- [ ] Module ownership still matches `AGENTS.md` and `specs/MODULES.md`.

### Specs

- [ ] Behavior changes are reflected in the matching spec.
- [ ] Rule changes update `specs/RULES.md` when needed.
- [ ] Event changes update `specs/EVENTS.md` when needed.
- [ ] Response changes update `specs/RESPONSES.md` when needed.
- [ ] Stats changes update `specs/STATS.md` when needed.

### Area checks

- [ ] Dataplane changes still match `AGENTS.md`, `specs/MODULES.md`, and generated-file rules.
- [ ] Go changes still match the relevant repo skills such as `go-abstraction`, `go-coding-style`, `go-logging`, or `go-rest-api`.
- [ ] Web changes still match backend/spec contracts and `skills/web-console`.
- [ ] Agent workflow content was not added to `docs/` or `specs/`.

### Verify

- [ ] Relevant tests or builds were run.
- [ ] Skipped verification includes a reason.
- [ ] Generated artifacts were regenerated when required.

Use these commands when they fit the changed area:

- backend: `go test ./...`
- `bpf/` or `internal/dataplane/`: `make test`
- `web/`: `npm --prefix web run build`
- generated dataplane artifacts: `go generate ./internal/dataplane` or `make test`

State clearly whether verification was:

- not run
- passed
- environment-blocked
- insufficient

## Output

Findings first, highest severity first.

Use this structure for file-backed reviews or long review replies:

```md
# <title>

## Findings

## Scope

## Spec

## Area

## Test

## Verdict
```

Rules:

- If there are no findings, say `No findings`.
- Reference concrete files and commands.
- Keep descriptions simple and precise.
- Do not restate full project rules or specs; point to the source file.

## File-backed reviews

Prefer `.agent/reviews/YYYYMMDD-<slug>.md` for new review files.
Start from `.agent/templates/review.md` when useful.
Use `make ai-review` for a local review pass.
