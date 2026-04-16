---
name: setup-go-repo
description: Define a clean Go repository layout, with clear structure for code, docs, tests, API, and deployment assets.
---

## When to use this

Use when bootstrapping a Go repository or adjusting its directory structure.

## Goal

Keep the repository structure simple, predictable, and easy to extend.

## Scope

This skill only defines repository layout and directory responsibilities.

## Do

- Separate code, docs, tests, configs, and deployment assets
- Keep executable entrypoints distinct from library code
- Prefer a small number of clear directories
- Keep names stable and responsibility-oriented

## Do not

- Do not put business implementation guidance in this skill
- Do not create placeholder directories without a real owner
- Do not mix deployment files into Go package directories
- Do not centralize all tests into one folder

## Recommended layout

Use these top-level directories when needed:

- `cmd/`
- `internal/`
- `pkg/`
- `api/`
- `configs/`
- `docs/`
- `scripts/`
- `deploy/`
- `build/`
- `test/`

## Directory guidance

- `cmd/`: one directory per executable, such as `cmd/server/` or `cmd/agent/`
- `internal/`: main application code that should not be imported from outside the repo
- `pkg/`: reusable packages only when they are intentionally public and stable
- `api/`: HTTP or RPC interface definitions, OpenAPI specs, protobuf, JSON schema, or generated contract files
- `configs/`: sample configs, local configs, and environment-specific config templates
- `docs/`: architecture, module boundaries, operations notes, and design records
- `scripts/`: developer and CI helper scripts
- `deploy/`: Kubernetes manifests, Helm charts, systemd units, Compose files, or Terraform for delivery
- `build/`: packaging assets such as Dockerfiles, image build context, release packaging, or build metadata
- `test/`: integration tests, end-to-end tests, fixtures, test data, and cross-module harnesses

## Test layout

- Keep unit tests next to the code they verify
- Use `test/` only for tests or assets that span packages or require external setup
- Do not move normal package `_test.go` files into `test/`

## Done when

- A new file has an obvious home
- API files, tests, and deployment assets are easy to find
- Code and operational assets are not mixed together
- The structure can grow without immediate reorganization
