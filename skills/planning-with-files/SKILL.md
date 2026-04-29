---
name: planning-with-files
description: Inspect the current code and specs first, then prepare a short execution-ready implementation plan with progress tracking. Use it even in Plan Mode when the user wants a file-backed plan.
---

## When to use this

Use when the user wants a plan written to a file before implementation.

Typical triggers:

- inspect first
- identify affected files
- sequence the work
- define verification
- track progress

## Goal

Write a short implementation plan.

- Prefer `.agent/plans/` for new plan files
- Start from `.agent/templates/plan.md` when useful
- Do not put agent plans in `docs/` or `specs/`
- Do not turn the plan into a product brief

## Repo map

- `cmd/`: entrypoints
- `internal/`: runtime modules
- `bpf/`: XDP/BPF; usually paired with `internal/dataplane/`
- `configs/`: config files
- `deploy/`: deployment assets
- `docs/`: technical docs
- `specs/`: product contracts
- `web/`: frontend
- `skills/`: agent workflow rules

## Rules

1. Inspect relevant code, tests, configs, docs, and specs first.
2. Write only the change delta.
3. Keep steps concrete and ordered.
4. Add a progress checklist.
5. Match verification to the touched area:
   - backend: `go test ./...`
   - `bpf/` or `internal/dataplane/`: `make test`
   - `web/`: `npm --prefix web run build`
   - generated dataplane artifacts: `go generate ./internal/dataplane` or `make test`
   - agent-rule-only changes: diff review is usually enough
6. Keep descriptions short and precise.

## Workflow

1. Identify the repo areas and files involved.
2. Record only confirmed facts that affect the change.
3. List the real gaps.
4. Write ordered steps with affected files.
5. Add progress items.
6. Add verification steps.
7. Prefer `.agent/plans/YYYYMMDD-<slug>.md` for new plan files.

## Output format

Use this section order:

```md
# <title>

## Summary

## State

## Gaps

## Plan

## Progress

## Verify
```

## Section rules

- `Summary`: one short paragraph
- `State`: confirmed facts only
- `Gaps`: real unknowns or mismatches only
- `Plan`: ordered steps; each step names affected files
- `Progress`: one checkbox per plan step
- `Verify`: concrete commands or checks

Step format:

```md
1. <action>

   Files: `<file>`, `<file>`

   Note: <short reason>
```

Progress format:

```md
- [ ] Step 1: <short action>
- [ ] Step 2: <short action>
```

## Output rules

- Keep it concise.
- Keep descriptions simple and precise.
- Mention only relevant files.
- Mention spec updates briefly when needed.
- Put assumptions in `Gaps` or inline in `Plan`.
