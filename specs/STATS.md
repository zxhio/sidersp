# Stats

This document defines the diagnostic stats model exposed by the control plane
and console.

The goal is not to mirror kernel counters one-to-one on the page. The goal is
to organize stats into a stable troubleshooting flow that operators can read
from ingress to response execution.

## Diagnostic Stages

Stats are grouped in this fixed order:

| Stage | Meaning |
|-------|---------|
| `ingress` | Packet reached the dataplane |
| `parse` | Packet parsing and protocol validation |
| `match` | Candidate selection and final rule match |
| `observe` | Ringbuf observation delivery |
| `tx_same_interface` | Same-interface kernel TX, mainly `tcp_reset` via `XDP_TX` |
| `xsk_redirect` | Redirect to XSK for user-space response handling |
| `redirect_egress` | Redirect to configured egress interface |

The stage order is the default troubleshooting order.

## Metric Contract

Each metric belongs to exactly one stage and carries one of three roles:

- `traffic`: input or pass-through volume
- `success`: successful execution at that stage
- `failure`: failed execution at that stage

Current metric mapping:

| Stage | Metric | Role | Meaning |
|-------|--------|------|---------|
| `ingress` | `rx_packets` | `traffic` | Total packets seen by the XDP program |
| `parse` | `parse_failed` | `failure` | Packets rejected before matching due to parse or protocol validation failure |
| `match` | `rule_candidates` | `traffic` | Packets with a non-empty candidate set after index pre-filter |
| `match` | `matched_rules` | `success` | Packets that matched a rule |
| `observe` | `ringbuf_dropped` | `failure` | Observation events dropped because ringbuf reserve failed |
| `tx_same_interface` | `xdp_tx` | `success` | Same-interface kernel TX submissions |
| `tx_same_interface` | `tx_failed` | `failure` | Same-interface kernel TX failures |
| `xsk_redirect` | `xsk_tx` | `success` | Packets submitted to XSK |
| `xsk_redirect` | `xsk_failed` | `failure` | Total XSK redirect failures |
| `xsk_redirect` | `xsk_meta_failed` | `failure` | XDP metadata allocation/write failures before XSK redirect |
| `xsk_redirect` | `xsk_redirect_failed` | `failure` | `bpf_redirect_map()` failures for XSK redirect |
| `redirect_egress` | `redirect_tx` | `success` | Redirect submissions to the configured egress interface |
| `redirect_egress` | `redirect_failed` | `failure` | Redirect preparation failures before submit |
| `redirect_egress` | `fib_lookup_failed` | `failure` | `bpf_fib_lookup()` failures on redirect path |

## Important Semantics

- `xsk_tx` and `redirect_tx` mean the dataplane submitted work to the next hop.
  They do not prove the final response frame was physically transmitted.
- `xsk_failed` is a stage-level failure summary. The preferred troubleshooting
  fields are `xsk_meta_failed` and `xsk_redirect_failed`.
- Rule counts such as `total_rules` and `enabled_rules` are management-plane
  context. They are not dataplane diagnostic stages.

## Console / API Shape

The stats API exposes three views of the same state:

- `overview`: top-level rule counts, packet baseline, and the current primary issue stage
- `stages`: current values grouped by diagnostic stage
- `stage_histories`: history grouped by stage and metric

Legacy flat fields may be retained temporarily for frontend migration, but the
grouped stage model is the canonical contract.

## Recommended Troubleshooting Order

1. Check `ingress.rx_packets` to confirm traffic is reaching the dataplane.
2. Check `parse.parse_failed` to see whether packets are being rejected before matching.
3. Compare `match.rule_candidates` and `match.matched_rules` to judge rule selection quality.
4. If response handling is involved, check `xsk_redirect` before checking user-space response results.
5. If redirect egress is enabled, check `redirect_egress` and inspect `fib_lookup_failed` before broader TX debugging.
