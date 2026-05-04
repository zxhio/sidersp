# Analysis

This document defines the external analysis export contract.

The `analysis` module in SideRSP is not the deep-analysis engine itself. Its
responsibility stops at exporting selected original packets to one external
analysis interface for downstream systems such as Suricata or Joy.

## Scope

- Consume selected XSK envelopes from the dataplane-owned XSK runtime
- Preserve the original packet bytes required by downstream analyzers
- Normalize and export selected packets to one configured analysis interface
- Expose export failures and backpressure as local diagnostics

Out of scope:

- Running Suricata, Joy, or any other external analyzer inside this module
- Ingesting or storing analyzer results
- Rule management
- Response execution
- Upstream platform orchestration

## Export Model

The export contract is intentionally small:

- Input is the original packet redirected through XSK
- Output is best-effort write to one configured analysis interface
- Export ordering is only required within the local worker path that handles a
  given envelope stream
- Export failures must not block dataplane progress or response execution
- Response remains the primary synchronous consumer on the XSK worker; analysis
  must stay on an asynchronous side path after response dispatch

The current contract does not define multi-interface fan-out or analyzer-side
session management.

## Selection Boundary

Selection happens before export.

- `dataplane` and `xsk` decide which packets are available to the `analysis`
  consumer
- `analysis` exports only the packets it receives
- Analyzer-side filtering after the configured interface is outside this
  contract

## Backpressure And Failure

Analysis export is best-effort.

- Queue saturation may cause export-side drops or skips
- If analysis needs to retain packet bytes after dispatch, it must copy or
  buffer them inside the analysis path
- Export failure must be observable locally
- Export failure must not block the response worker path
- Export failure must not change the dataplane verdict for the original packet

## Integration Boundary

SideRSP is a service inside a larger platform. The `analysis` module only
provides a packet-export boundary.

Downstream analyzer deployment, alert handling, storage, correlation, and
platform workflows belong to external systems or other service modules.

## Related Contracts

- Module boundaries: `MODULES.md`
- Response execution: `RESPONSES.md`
- Event structure: `EVENTS.md`
