---
name: implement-rule-model
description: Implement the minimal rule model, file loading, normalization, and validation based on RULES.md.
---

## When to use this

Use when creating or changing rule structs, rule loading, or rule validation.

## Goal

Turn `RULES.md` into stable Go data structures and minimal loading logic.

## Scope

This skill only covers rule model implementation in the control plane.

## Inputs

- `RULES.md`
- `AGENTS.md`
- sample `configs/rules.json`

## Do

- Define rule-related Go structs
- Match field names and semantics from `RULES.md`
- Load rules from local file
- Validate required fields
- Validate CIDR format
- Validate port range
- Validate action values used in the current phase
- Normalize rules into a stable in-memory form
- Preserve rule priority semantics
- Preserve first-match semantics at the model level where needed

## Do not

- Do not add Web management
- Do not add database storage
- Do not add dynamic hot reload unless explicitly requested
- Do not extend the rule syntax beyond `RULES.md`
- Do not guess extra fields

## Required fields

Support the current minimal rule structure:

- `id`
- `name`
- `enabled`
- `priority`
- `match.vlans`
- `match.src_prefixes`
- `match.dst_prefixes`
- `match.src_ports`
- `match.dst_ports`
- `match.features`
- `response.action`

## Validation rules

At minimum validate:

- `id` is present
- `name` is present
- `priority` is valid
- prefixes are valid CIDRs
- ports are within range
- action is allowed in the current phase

## Done when

- Rules can be loaded from file
- Invalid rules fail clearly
- In-memory model is stable and simple
- Semantics stay aligned with `RULES.md`
- No extra rule syntax is added