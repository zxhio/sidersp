---
name: plan-workflow
description: Inspect repo sources, write or update concise file-backed plan routing, and split executable work into separate task files with progress tracking.
---

## When to use this

Use when the user wants a plan saved to a file, asks to inspect before acting,
or asks for work to be split into checkpoints.

Do not use for tiny edits unless the user asks for a file-backed plan.

## Goal

Keep planning useful and short.

- Restore current context before planning.
- Read source files before proposing work.
- Put human decisions near the top.
- Keep the parent plan small and use it as a route map.
- Put executable tasks in separate task files.
- Keep each task small, verified, and commit-ready.
- Update progress and handoff context in the task file when a task is executed.

## Core rule

Plans are not product contracts.

Any API, field, semantic, persistence, event, stats, config, or BPF ABI change
must be called out as `Spec Impact` and confirmed before implementation.

When the user says business details are undecided, leave them as decisions.
Do not close choices by copying current code into the contract.

## Workflow

### 0. Restore

Before writing or updating a plan, inspect:

- `git status --short`
- relevant `.agent/plans/`
- relevant specs and docs
- affected code, tests, configs, and generated-file rules

Mark stale or conflicting context in the plan.

### 1. Decide plan shape

Use the smallest useful shape:

- `Roadmap`: broad direction; not executable.
- `Decision`: open questions and options; no coding approval.
- `Checkpoint`: confirmed unit that can be implemented and committed.
- `Skeleton`: small implementation slice used to expose real unknowns.

Do not over-explain the shape in the plan. Put the chosen shape in `Review Brief`.

### 2. Plan

Write or update `.agent/plans/YYYYMMDD-<slug>.md`.

Parent plans should include:

- `Review Brief`
- `Confirmations`
- `Sources`
- `State`
- `Spec Impact`
- `Task Index`
- `Progress`
- `Verify`
- `Handoff Context`

Omit empty sections. Keep descriptions short and precise.

When one plan naturally splits into multiple tasks, do not expand every task in
the parent plan. Create one task file per executable task:

```text
.agent/plans/YYYYMMDD-<slug>.md
.agent/plans/YYYYMMDD-<slug>-task-01-<name>.md
.agent/plans/YYYYMMDD-<slug>-task-02-<name>.md
```

The parent plan routes to task files and records overall progress. Each task
file owns detailed files, boundaries, acceptance, verification, execution log,
and handoff context.

### 3. Confirm or execute

If the user asked only for a plan, stop after writing it.

If the user asked to proceed and the task is low risk, implement after writing
the task file. Update the task file's `Progress`, `Verify`, and
`Handoff Context`, then update the parent plan's `Task Index`.

Stop for confirmation when:

- `Spec Impact` is not `None`
- a business decision is open
- the step touches BPF ABI, persistence migration, deploy behavior, or public API
- the file boundary is not clear

## Plan fields

Put this near the top:

```md
## Review Brief

Status: Draft

Shape:
- Roadmap | Decision | Checkpoint | Skeleton

Goal:
- <one sentence>

My judgment:
- <approve, revise, split, defer, or block, with one short reason>

Recommended next action:
- <what should happen next>

Main risk:
- <short risk>

Suggested commit split:
- `<type>(<scope>): <subject>` - <files or area>
```

Use confirmations only for real decisions:

```md
## Confirmations

- [ ] <decision needed>
  - Recommendation: <approve, reject, defer, or user decision>
  - Reason: <short reason>
  - Impact: <what changes if confirmed>
```

Use this in parent plans to route work:

```md
## Task Index

| Task | File | Status | Spec Impact | Commit |
|---|---|---|---|---|
| 01 <name> | `.agent/plans/YYYYMMDD-<slug>-task-01-<name>.md` | Draft | None | `<commit>` |
```

Use this in each executable task file:

```md
## Task

Goal:
- <what this step achieves>

Files:
- `<file>`

Boundary:
- Change: <what may change>
- Keep: <what must not change>

Spec Impact:
- None | Clarification | Contract change

Acceptance:
- <done condition>

Verify:
- `<command>`

Commit:
- `<type>(<scope>): <subject>`
```

For decision-only work, use a table:

```md
| Topic | Current spec | Current implementation | Decision needed | Options | Default | Impacted files |
|---|---|---|---|---|---|---|
```

Use `Default: user decision` when the business meaning is not obvious.

## Verification guide

- specs or plans only: diff review and `bash scripts/ai-review.sh`
- backend: `go test ./...`
- `bpf/` or `internal/dataplane/`: `make test`
- generated dataplane artifacts: `go generate ./internal/dataplane` or `make test`
- `web/`: `npm --prefix web run build`
- agent-rule-only changes: diff review is usually enough

## Output rules

- Prefer `.agent/plans/` for plan files.
- Tell the user when the plan path is ignored by git.
- Do not put plans in `docs/` or `specs/`.
- Use source-backed statements; do not infer product contracts from code when a
  matching spec exists.
- Keep parent plan files small and high level.
- Put detailed executable work in task files.
- Keep skeleton work minimal and explicitly list non-goals.
