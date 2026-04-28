---
name: planning-with-files
description: Inspect the current code and specs first, then prepare a short execution-ready implementation plan with progress tracking. Use it even in Plan Mode when the user wants a file-backed plan.
---

## When to use this

Use when the user wants a plan written to a file before implementation, especially for code changes that need:

- file inspection first
- affected-file identification
- implementation sequencing
- validation steps
- progress tracking during execution

Do not skip this skill just because the conversation is already in Plan Mode.

## Goal

A plan file in this repo is a delivery tool, not a business document.

Its job is to make the next implementation pass easy:

- what to change
- where to change it
- in what order
- how to verify it
- how progress will be tracked

Do not turn the plan file into a product brief, architecture essay, or duplicate spec.

## Core rules

1. Inspect first

   Read the relevant code, tests, docs, configs, and specs before writing the plan.

2. Write only implementation delta

   The plan should describe this change only.

   Do not restate stable repo facts that already live in:

   - `AGENTS.md`
   - `specs/*.md`
   - existing code comments or tests

3. Keep it actionable

   Every plan step must be implementable without further interpretation.

   Prefer:

   - subsystem-level edits
   - exact behavior changes
   - concrete validation

   Avoid:

   - broad business discussion
   - long design rationale
   - roadmap material not needed for this change

4. Include progress tracking

   The plan must contain a checkbox list that maps directly to the implementation steps.

5. Prefer simple structure

   Keep the file short unless complexity truly requires more detail.

6. Respect collaboration mode

   If the current mode forbids repo mutations, still use this skill to drive the plan structure and content.

   In that case:

   - do the same inspection work
   - prepare the exact plan content
   - do not write the file yet
   - make it easy to drop into the target plan file unchanged later

## What a good plan file contains

- short summary
- confirmed current-state facts that matter
- only the real gaps or mismatches
- ordered implementation steps
- progress checklist
- verification steps

## What a plan file should not contain

- repeated module boundary explanations
- repeated rule/spec definitions unless this change modifies them
- long file-by-file inventories with no decisions
- business requirements prose
- future phases unless they directly constrain this implementation

## Workflow

1. Locate and inspect

   Find the relevant:

   - code paths
   - tests
   - specs
   - config or API shapes

2. Capture only important current state

   Write only confirmed facts that affect implementation.

3. Identify the real gaps

   Record only missing, inconsistent, or unclear implementation points.

4. Write ordered implementation steps

   Each step should say:

   - what to change
   - where to change it
   - why it matters

5. Add progress checklist

   One checkbox item per implementation step.

6. Add verification

   Include practical commands, tests, or manual checks.

## Output format

Use this exact section order:

```md
# <title>

## Summary

## State

## Gaps

## Plan

## Progress

## Verify
```

## Section guidance

### Summary

One short paragraph.

State the recommended implementation direction.

### State

List only confirmed facts from inspected files.

Keep it short.

### Gaps

List only real implementation gaps, inconsistencies, or open assumptions.

Keep it short.

### Plan

Use ordered steps.

Each step must include affected files.

Format:

```md
1. <action>

   Files: `<file>`, `<file>`

   Note: <short implementation reason>
```

### Progress

Use checkbox items only.

Each item must map to one Plan step.

Format:

```md
- [ ] Step 1: <short action>
- [ ] Step 2: <short action>
```

### Verify

List concrete validation steps.

Prefer commands, tests, and expected outcomes.

## Output rules

- Keep it concise.
- Prefer implementation language over business language.
- Mention only files that are actually relevant.
- If specs must change, say so briefly; do not rewrite the spec into the plan.
- If assumptions are necessary, put them in `Gaps` or inline in `Plan`.
- If the task is small, keep the whole plan small.

## Execution rules

When the user later asks to implement:

- follow the Plan order
- use the Progress checklist to track completion
- keep status updates short
- run or report the Verify steps at the end

If this skill was used earlier during Plan Mode without writing the file:

- use that plan content as the source of truth
- write or update the plan file first when edits become allowed
- then implement from it
