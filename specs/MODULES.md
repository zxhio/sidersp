# Modules

This document defines the system module contract. For the short agent-facing summary, see `../AGENTS.md`.

## Module Map

| Module | Path | Status | Responsibility |
|--------|------|--------|----------------|
| `dataplane` | `internal/dataplane/`, `bpf/` | active | Fast-path packet parsing, classification, rule matching, XDP verdicts, kernel TX, XSK redirect, event output |
| `controlplane` | `internal/controlplane/` | active | Rule loading, rule validation, runtime state, statistics aggregation, workflow orchestration |
| `console` | `internal/console/`, `web/` | active | REST API, status display, statistics view, rule CRUD |
| `config` | `internal/config/` | active | Local configuration loading and validation |
| `logging` | `internal/logging/` | active | Runtime log output setup, file rotation, and log-level management |
| `model` | `internal/model/` | active | Shared data models used across modules |
| `rule` | `internal/rule/` | active | Shared rule schema used by controlplane, console, and dataplane compilation |
| `analysis` | `internal/analysis/` | planned | Deep analysis task submission and result ingestion |
| `response` | `internal/response/` | active | User-space response execution and result feedback |

Deployment artifacts under `deploy/`, `scripts/`, and deployment documents are
repository operations assets, not runtime modules. They may install binaries,
configuration, rule files, and service manager metadata, but they must not own
rule matching, analysis decisions, response decisions, or core pipeline
orchestration.

## Dependency Rules

Allowed direction:

```text
console/web -> controlplane -> dataplane
console/controlplane/dataplane -> rule
cmd/console -> logging
controlplane -> analysis
controlplane -> response
dataplane -> event output / XSK redirect
```

Hard rules:

- `dataplane` must not depend on `console`, `web`, or presentation logic
- `dataplane` must not own policy orchestration
- `console` / `web` must not perform rule matching, analysis decisions, or response decisions
- `analysis` must not manage rules or execute responses
- `response` must not decide whether a response should happen
- `logging` must not perform rule matching, analysis decisions, response decisions, or pipeline orchestration

## Dataplane

Responsible for fast-path processing.

Owns:

- Mirrored packet parsing
- Basic classification and feature extraction
- Lightweight rule matching
- XDP verdict selection
- Kernel TX actions such as `tcp_reset`, including same-interface `XDP_TX` and configured egress-interface redirect
- XSK redirect and XSK fd registration for actions that need full packet context
- Observation event output
- Dataplane interface setup required for packet capture, including promiscuous
  mode

Does not own:

- Rule lifecycle management
- Complex workflow orchestration
- Deep analysis
- User-space response execution
- Presentation or query APIs

## Controlplane

Responsible for runtime coordination.

Owns:

- Rule and runtime configuration management
- Rule validation
- Validating rule actions before dataplane synchronization
- Runtime state maintenance
- Statistics aggregation
- Coordination between dataplane, analysis, response, and console

Does not own:

- Raw packet parsing
- BPF/XDP fast-path logic
- Page rendering
- Low-level response execution

## Console And Web

Responsible for management and visibility.

Owns:

- REST API
- Status display
- Rule CRUD
- Statistics view
- Event query after event storage is introduced
- Response result query after response results are introduced

Does not own:

- Packet processing
- Rule matching
- Analysis decisions
- Response decisions
- Core pipeline orchestration

## Analysis

Planned module for deep analysis integration.

Owns:

- Analysis task submission
- Analysis input/output normalization
- Analysis result ingestion

Does not own:

- Front-path classification
- Rule management
- Response execution

## Response

Module for active user-space response execution.

Current implementation status: XSK metadata decoding, response packet builders,
response execution, bounded in-memory response result buffering, worker-group
lifecycle, runtime assembly, Linux AF_XDP ingress socket IO, and shared TX
backend selection exist. Same-interface builders still reject VLAN-tagged
frames and TCP SYN payloads until those response semantics are implemented.
Management-plane response result streaming is still planned.

Owns:

- User-space TX response execution
- AF_XDP RX worker loops, same-interface XSK TX handling, and alternate-egress
  TX backend selection for supported actions
- Response result recording
- Failure feedback

Does not own:

- Rule matching
- Response decision making
- BPF kernel TX actions

## Contract Documents

- Rule semantics: `RULES.md`
- Event structure: `EVENTS.md`
- Response action model: `RESPONSES.md`
