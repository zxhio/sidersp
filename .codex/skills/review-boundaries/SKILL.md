---
name: review-boundaries
description: Review changes against MODULES.md, AGENTS.md, and current phase scope to prevent scope creep and module boundary violations.
---

## When to use this

Use after implementing any task, or before merging a change.

## Goal

Check that the change stays within the current phase and respects module boundaries.

## Scope

This skill is for review only.

## Review checklist

### Module boundaries

Check that code stays inside the right module:

- dataplane only handles fast-path parsing, matching, and event output
- controlplane only handles rule management, state, and orchestration
- analysis only handles backend analysis integration
- response only handles action execution
- console only handles management and display

### Scope control

Check that the change does not introduce:

- unrelated platform features
- unnecessary abstractions
- database dependency without clear need
- Web/UI logic in core modules
- control logic inside dataplane
- core pipeline logic inside console

### Model alignment

Check that implementation matches:

- `RULES.md`
- `EVENTS.md`
- `RESPONSES.md`

Do not allow silent drift in field names or semantics.

### Simplicity

Prefer:

- smaller changes
- direct implementations
- explicit validation
- observable logs or status
- minimal tests for new core logic

## Output format

When reviewing, report:

- what changed
- whether boundaries are respected
- any scope creep found
- any document mismatch found
- the smallest correction needed

## Done when

- The change matches the current phase
- Module boundaries remain clear
- Model drift is identified if present
- Any needed follow-up is explicit and minimal