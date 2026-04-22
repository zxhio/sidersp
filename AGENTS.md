# AGENTS

Side-path analysis and active response platform for mirrored traffic.

## Module Boundaries

| Module | Responsibility |
|--------|----------------|
| `dataplane` | Data plane: XDP packet parsing, rule matching, synchronous TX (`tcp_reset`), XSK redirect, event output |
| `controlplane` | Control plane: rule management, state maintenance, statistics aggregation, workflow orchestration |
| `analysis` | Planned deep analysis integration: analysis task submission and analysis result ingestion |
| `response` | Planned response execution: XSK TX response, action execution, result feedback |
| `console` / `web` | Management plane: REST API, status display, statistics view, rule CRUD |

Hard constraints:

- Do not stack logic across module boundaries
- Do not put control logic in the data plane
- Do not put core pipeline logic in `console` / `web`
- Do not execute rule, analysis, or response decisions in the presentation layer
- When changing interfaces, events, rules, or response semantics, update the corresponding spec document

Detailed module responsibilities are defined in `specs/MODULES.md`.

## Spec Documents

| Document | Content |
|----------|---------|
| `specs/MODULES.md` | Module division, responsibilities, and boundaries |
| `specs/RULES.md` | Rule model, matching semantics, and action list |
| `specs/EVENTS.md` | Data plane observation event structure |
| `specs/RESPONSES.md` | Response action model and execution path |
