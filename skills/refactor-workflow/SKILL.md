---
name: refactor-workflow
description: Use for multi-step refactors that need restored context, source-backed planning, human confirmation, task progress, verification, and small commits.
---

## When to use this

Use when the user asks for a refactor, split, migration, module extraction, or multi-step cleanup.

Do not use for small single-file edits unless the user asks for a plan or checkpointed workflow.

## Goal

Run refactors as controlled, reviewable steps.

- Restore previous agent context first.
- Read specs and architecture before proposing structure.
- Make the plan readable for humans.
- Require human confirmation before coding.
- Keep each task small, verified, and commit-ready.
- Persist progress and handoff context after every task.

## Core rule

Refactoring preserves behavior by default.

Any API, field, semantic, persistence, event, stats, config, or product contract change must be called out as `Spec Impact` and confirmed by the user before implementation.

## Workflow

### 0. Restore

Before writing a plan, inspect:

- `git status --short`
- relevant `.agent/plans/`
- relevant `.agent/reviews/`
- existing `Handoff Context`, `Progress`, `Gaps`, and `Decisions`

Mark stale or conflicting context in the plan.

### 1. Inspect

Read source-of-truth files before planning:

- `AGENTS.md`
- `specs/MODULES.md`
- relevant `specs/`
- relevant `docs/architecture/`
- relevant code, tests, configs, and generated-file rules

Do not infer product contracts from code when a matching spec exists.

### 2. Plan

Write or update `.agent/plans/YYYYMMDD-<slug>.md`.

Use `.agent/templates/plan.md` when useful.

The plan must include:

- a top `Review Brief` for human review
- the agent's judgment and recommended next action
- all user confirmations grouped in one checklist
- a short change summary and suggested commit split
- recovered context
- sources with `Used for` notes
- evidence for current state
- invariants
- spec impact
- decisions
- task plan
- progress
- verification
- handoff context

Keep descriptions short and precise.
Put human decision material before evidence. Put AI recovery details after the task plan.

### 3. Confirm

Stop after writing the plan.

Ask the user to confirm:

- every unchecked item in `Confirmations`
- task split and order
- spec impact
- allowed automation scope
- whether commits may be created after each verified task

Do not start coding until the user confirms.

### 4. Execute Task Loop

For each confirmed task:

1. Re-check `git status --short`.
2. Re-read affected files if the worktree changed.
3. Change only files named by the task unless a new dependency is discovered.
4. If new spec impact appears, stop and ask for confirmation.
5. Run the task's verification.
6. Update the plan:
   - `Progress`
   - task `Execution Log`
   - `Handoff Context`
   - verification result
7. Review the diff.
8. If commit permission was granted, stage only task files and commit with a focused Conventional Commit message.
9. Continue to the next confirmed task.

### 5. Review

Before handoff or commit, use `skills/agent-review` when AI-authored code changed.

The review must check:

- implementation matches the confirmed plan
- decisions were not violated
- spec impact was handled as approved
- verification is sufficient or clearly skipped
- handoff context is useful for the next agent run

## Refactor plan fields

Put this at the top of every plan:

```md
## Review Brief

Status: Draft

Goal:
- <one sentence>

My judgment:
- <approve, revise, split, or block, with one short reason>

Recommended next action:
- <what the user should approve or reject next>

Main risk:
- <short risk>

Change summary:
- <area>: <short change>

Suggested commit split:
- `<type>(<scope>): <subject>` - <files or area>

## Confirmations

- [ ] <decision needed>
  - Recommendation: <approve, reject, defer, or revise>
  - Reason: <short reason>
  - Impact: <what changes if confirmed>
```

Use these fields for each task:

```md
### Step N: <name>

Goal:
- <what this step achieves>

Files:
- `<file>`

Boundary:
- Change: <what may change>
- Keep: <what must not change>

Acceptance:
- <what means this step is done>

Verify:
- `<command>`

Commit:
- `<type>(<scope>): <subject>`
```

## Spec Impact values

Use one of:

- `None`: no contract change, no spec edits.
- `Clarification proposed`: spec wording may be clarified; requires confirmation.
- `Contract change proposed`: behavior/API/field/semantic change; requires confirmation.
- `Blocked`: cannot proceed without product decision.

Default to `None` for pure refactors.

## Handoff Context

Update this after every task.

Include:

- completed work
- changed files
- verification result
- open items
- next action
- any stale assumptions

Write conclusions, not command transcripts.
