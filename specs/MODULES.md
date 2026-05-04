# Modules

This document defines the system module contract. For the short agent-facing summary, see `../AGENTS.md`.

## Module Map

| Module | Path | Status | Responsibility |
|--------|------|--------|----------------|
| `dataplane` | `internal/dataplane/`, `bpf/` | active | Fast-path packet parsing, classification, rule matching, XDP verdicts, kernel TX, XSK redirect, event output |
| `controlplane` | `internal/controlplane/` | active | Rule loading, rule validation, runtime state, statistics aggregation, workflow orchestration |
| `console` | `internal/console/`, `web/` | active | REST API, local debug UI, status display, statistics view, rule CRUD |
| `config` | `internal/config/` | active | Local configuration loading and validation |
| `logging` | `internal/logs/` | active | Runtime log output setup, file rotation, and log-level management |
| `model` | `internal/model/` | active | Shared data models used across modules |
| `rule` | `internal/rule/` | active | Shared rule schema used by controlplane, console, and dataplane compilation |
| `frameio` | `internal/frameio/` | active | AF_XDP and AF_PACKET frame I/O implementations, read/write primitives, and optional borrowed-send capabilities |
| `xsk` | `internal/xsk/` | active | XSK metadata decode, queue workers, queue-local socket registration, and XSK consumer dispatch |
| `analysis` | `internal/analysis/` | active | Selected packet export to one external analysis interface |
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
dataplane -> xsk
xsk -> frameio
xsk -> analysis
xsk -> response
analysis -> frameio
response -> frameio
cmd/console -> logging
controlplane -> analysis
controlplane -> response
dataplane -> event output / XSK redirect
```

Hard rules:

- `dataplane` must not depend on `console`, `web`, or presentation logic
- `dataplane` must not own policy orchestration
- `frameio` must not decide whether a response or analysis should happen
- `xsk` must not decide whether a response or analysis should happen
- `console` / `web` must not perform rule matching, analysis decisions, or response decisions
- `analysis` must not manage rules or execute responses
- `response` must not decide whether a response should happen
- `logging` must not perform rule matching, analysis decisions, response decisions, or pipeline orchestration
- `web` is a local debug and integration aid; it must not evolve into the primary upstream platform control plane for this service

## Dataplane

Responsible for fast-path processing.

Owns:

- Mirrored packet parsing
- Basic classification and feature extraction
- Lightweight rule matching
- XDP verdict selection
- Kernel TX actions such as `tcp_reset` and `icmp_port_unreachable`, including same-interface `XDP_TX` and configured egress-interface redirect
- XSK redirect, XSK fd registration, and XSK runtime lifecycle for actions that need full packet context
- Observation event output
- Dataplane interface setup required for packet capture, including promiscuous
  mode

Does not own:

- Rule lifecycle management
- Complex workflow orchestration
- Deep analysis
- User-space response execution
- Presentation or query APIs

## XSK

Responsible for user-space packet transport after dataplane redirect.

Owns:

- XSK metadata decode
- Queue worker loops
- Queue-local socket registration
- Queue-parallel dispatch to response and analysis consumers, with queue-local
  synchronous response handling first and analysis submission on a side path
- Borrowed-frame receive handoff for queue-local response hot paths

Does not own:

- Frame I/O implementation details
- Rule matching
- Rule lifecycle management
- Response packet construction
- Analysis decisions
- Presentation or query APIs

## Frame I/O

Responsible for concrete packet frame transport primitives.

Owns:

- AF_XDP socket create, close, and queue binding
- AF_PACKET frame send paths
- Shared frame read/write capability interfaces, including borrowed-frame
  handling for queue-local hot paths
- Optional borrowed-send optimizations where supported

Does not own:

- Rule matching
- Rule lifecycle management
- Response decisions
- Analysis decisions
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
- Local debug and validation UI
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
- Upstream multi-service platform control

## Analysis

Module for external analysis export.

Current implementation status: selected XSK packets are exported best-effort to
one configured analysis interface.

Owns:

- XSK analysis-envelope consumption
- Original-packet normalization for export
- Best-effort packet export to one configured analysis interface
- Export failure accounting and feedback

Does not own:

- Front-path classification
- Rule management
- Response execution
- Downstream Suricata, Joy, or any other external analysis lifecycle
- Analysis result storage or ingestion

The analysis module boundary stops at packet export. Downstream processing on
that interface belongs to other modules or external systems.

## Response

Module for active user-space response execution.

Current implementation status: XSK response consumer dispatch, response packet
builders, response execution, bounded in-memory response result buffering, and
sender selection across queue-local XSK TX or alternate egress frame I/O
exist. Same-interface builders still reject VLAN-tagged frames and TCP SYN
payloads until those response semantics are implemented.

Owns:

- User-space TX response execution
- Response-side sender selection for same-interface XSK TX and alternate-egress
  frame I/O for supported actions
- XSK response-envelope consumption
- Response result recording
- Failure feedback

Does not own:

- Rule matching
- Response decision making
- Frame I/O implementation details
- BPF kernel TX actions

## Contract Documents

- Analysis export semantics: `ANALYSIS.md`
- Rule semantics: `RULES.md`
- Event structure: `EVENTS.md`
- Response action model: `RESPONSES.md`
