# Stats

This document defines the diagnostic stats model exposed by the control plane
and console.

The goal is not to mirror kernel counters one-to-one on the page. The goal is
to organize stats into a stable troubleshooting flow from ingress through
user-space response execution.

## Diagnostic Stages

Stats are grouped in this fixed order:

| Stage | Meaning |
|-------|---------|
| `ingress` | Packet reached the dataplane |
| `parse` | Packet parsing and protocol validation |
| `match` | Candidate selection and final rule match |
| `observe` | Ringbuf observation delivery |
| `tx_same_interface` | Same-interface kernel TX, mainly `tcp_reset` via `XDP_TX` |
| `response_redirect` | Dataplane redirect of the original packet into XSK |
| `redirect_egress` | Dataplane redirect of a kernel-built response to the configured egress interface |
| `response_tx` | User-space response transmission through AF_XDP or AF_PACKET |

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
| `response_redirect` | `xsk_redirected` | `success` | Original packets submitted by BPF to XSK |
| `response_redirect` | `xsk_redirect_failed` | `failure` | Total XSK redirect-stage failures |
| `response_redirect` | `xsk_meta_failed` | `failure` | XDP metadata allocation or write failures before redirect |
| `response_redirect` | `xsk_map_redirect_failed` | `failure` | `bpf_redirect_map()` failures for XSK redirect |
| `redirect_egress` | `redirect_tx` | `success` | Redirect submissions to the configured egress interface |
| `redirect_egress` | `redirect_failed` | `failure` | Redirect preparation failures before submit |
| `redirect_egress` | `fib_lookup_failed` | `failure` | `bpf_fib_lookup()` failures on the redirect path |
| `response_tx` | `response_sent` | `success` | Total user-space response frames sent |
| `response_tx` | `response_failed` | `failure` | Total user-space response send failures |
| `response_tx` | `afxdp_tx` | `success` | User-space response frames sent through AF_XDP |
| `response_tx` | `afxdp_tx_failed` | `failure` | AF_XDP response path failures |
| `response_tx` | `afpacket_tx` | `success` | User-space response frames sent through AF_PACKET |
| `response_tx` | `afpacket_tx_failed` | `failure` | AF_PACKET response path failures |

## Important Semantics

- `xsk_redirected` means the dataplane submitted the original packet to XSK.
  It does not prove the final response frame was transmitted.
- `response_sent` and backend metrics in `response_tx` describe user-space TX,
  not dataplane redirect.
- `xsk_redirect_failed` is a stage-level failure summary. The preferred
  troubleshooting fields are `xsk_meta_failed` and
  `xsk_map_redirect_failed`.
- `response_sent = afxdp_tx + afpacket_tx`
- `response_failed = afxdp_tx_failed + afpacket_tx_failed`
- Rule counts such as `total_rules` and `enabled_rules` are management-plane
  context. They are not dataplane diagnostic stages.

## Console Config

Console stats config uses one collection interval and one raw-history retention
period:

```yaml
console:
  listen_addr: 127.0.0.1:8080
  stats:
    collect_interval: 10s
    retention: 30d
```

- `collect_interval` is the raw runtime stats collection cadence.
- `retention` is the raw sampled-history retention window.
- The current console requires `collect_interval <= 10m`.
- The current console requires `retention >= 10m`.

## Console / API Shape

The stats API exposes:

- `overview`: top-level rule counts, packet baseline, and the current primary issue stage
- `stages`: current values grouped by diagnostic stage
- `stage_histories`: history grouped by stage and metric
- `range_seconds`: requested history range in seconds
- `collect_interval_seconds`: configured raw collection cadence
- `retention_seconds`: configured raw history retention
- `display_step_seconds`: actual bucket size used to build history points

The grouped stage model and flat metric keys above are the public contract.

The stats query is request-driven:

```text
GET /api/v1/stats?range_seconds=86400
```

Rules:

- `range_seconds` defaults to `600`
- `range_seconds` must be a positive multiple of `600`
- `range_seconds` must not exceed `retention`
- history points are aggregated on demand from retained raw samples

## Recommended Troubleshooting Order

1. Check `ingress.rx_packets` to confirm traffic is reaching the dataplane.
2. Check `parse.parse_failed` to see whether packets are being rejected before matching.
3. Compare `match.rule_candidates` and `match.matched_rules` to judge rule selection quality.
4. If response handling is involved, check `response_redirect` to confirm BPF handed the original packet to XSK.
5. If user-space response handling is involved, check `response_tx` to separate AF_XDP and AF_PACKET failures.
6. If redirect egress is enabled for kernel TX, check `redirect_egress` and inspect `fib_lookup_failed` before broader TX debugging.
