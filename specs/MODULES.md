# Modules

This document defines the system module contract. For the short agent-facing summary, see `../AGENTS.md`.

## Module Map

| Module | Path | Status | Responsibility |
|--------|------|--------|----------------|
| `dataplane` | `internal/dataplane/`, `bpf/` | active | Fast-path packet parsing, classification, rule matching, XDP verdicts, synchronous TX, XSK redirect, event output |
| `controlplane` | `internal/controlplane/` | active | Rule loading, rule validation, runtime state, statistics aggregation, workflow orchestration |
| `console` | `internal/console/`, `web/` | active | REST API, status display, statistics view, rule CRUD |
| `config` | `internal/config/` | active | Local configuration loading and validation |
| `model` | `internal/model/` | active | Shared data models used across modules |
| `rule` | `internal/rule/` | active | Shared rule schema used by controlplane, console, and dataplane compilation |
| `analysis` | `internal/analysis/` | planned | Deep analysis task submission and result ingestion |
| `response` | `internal/response/` | skeleton | User-space response execution and result feedback |

## Dependency Rules

Allowed direction:

```text
console/web -> controlplane -> dataplane
console/controlplane/dataplane -> rule
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

## Dataplane

Responsible for fast-path processing.

Owns:

- Mirrored packet parsing
- Basic classification and feature extraction
- Lightweight rule matching
- XDP verdict selection
- Synchronous TX actions such as `tcp_reset`
- XSK redirect and XSK fd registration for actions that need full packet context
- Observation event output

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

Planned module for active response execution.

Current implementation status: package skeleton, XSK metadata decoding, worker
registration boundary, and pure response packet builders exist. The builders
reject VLAN-tagged frames and TCP SYN payloads until those response semantics
are implemented. A response execution core and bounded in-memory response
result buffer exist, and the worker boundary dispatches metadata-prefixed XSK
frames into that execution core. AF_XDP socket IO and management-plane response
result streaming are still planned.

Owns:

- User-space TX response execution
- AF_XDP RX/TX worker loops and XSK TX packet handling
- Response result recording
- Failure feedback

Does not own:

- Rule matching
- Response decision making
- BPF synchronous TX actions

## Contract Documents

- Rule semantics: `RULES.md`
- Event structure: `EVENTS.md`
- Response action model: `RESPONSES.md`
