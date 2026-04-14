---
name: setup-go-repo
description: Initialize the minimal Go repository skeleton for the bypass analysis and active response platform.
---

## When to use this

Use when bootstrapping the repository or reorganizing the project structure.

## Goal

Create the minimal Go project skeleton that matches AGENTS.md and leaves clear places for later module work.

## Scope

This skill is only for repository setup.

## Do

- Initialize the Go module
- Create the base directories used by the project
- Add the minimal program entry
- Add basic config and sample rules files
- Add a minimal Makefile
- Keep the repository layout aligned with AGENTS.md

## Do not

- Do not implement XDP logic
- Do not implement Web UI
- Do not implement database support
- Do not add unnecessary frameworks
- Do not change module boundaries

## Expected structure

Create or preserve these top-level areas:

- `cmd/`
- `internal/`
- `configs/`
- `docs/`
- `scripts/`
- `test/`

Keep module code separated under `internal/`:

- `dataplane/`
- `controlplane/`
- `analysis/`
- `response/`
- `console/`
- `config/`
- `model/`
- `util/`

## Minimal outputs

- `go.mod`
- `cmd/.../main.go`
- `configs/config.yaml`
- `configs/rules.json`
- `Makefile`

## Done when

- The repository builds
- The directory layout is clear
- The minimal entry can run
- Config and rules sample files exist
- No unrelated functionality is introduced