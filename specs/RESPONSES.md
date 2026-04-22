# Responses

This document defines the active response action contract and execution paths.

Rules reference responses through `response.action`. The control plane validates the action name. The dataplane sync path encodes it as the action code defined in `RULES.md`.

## Action Contract

| Action | Code | Path | Current Status | Semantics |
|--------|------|------|----------------|-----------|
| `none` | `0` | dataplane pass | active | Match silently and continue with `XDP_PASS` |
| `alert` | `1` | dataplane observe | active | Emit an observation event and continue with `XDP_PASS` |
| `tcp_reset` | `2` | BPF synchronous TX | active | Build TCP RST in BPF and return `XDP_TX` |
| `icmp_echo_reply` | `3` | XSK TX | builder implemented, worker planned | Redirect the original packet to XSK; user space builds ICMP echo reply |
| `arp_reply` | `4` | XSK TX | builder implemented, worker planned | Redirect the original packet to XSK; user space builds ARP reply |
| `tcp_syn_ack` | `5` | XSK TX | builder implemented, worker planned | Redirect the original packet to XSK; user space builds TCP SYN-ACK |

Action names are stable snake-case API values. Numeric codes are the dataplane ABI and must stay synchronized with BPF definitions.

## Execution Paths

### Dataplane Pass

Used by `none`.

```text
packet -> BPF parse/match -> XDP_PASS
```

No response packet is generated and no observation event is required.

### Dataplane Observe

Used by `alert`.

```text
packet -> BPF parse/match -> ringbuf event -> XDP_PASS
```

The ringbuf event is only for observation, statistics, and audit.

### BPF Synchronous TX

Used by `tcp_reset`.

```text
packet -> BPF parse/match -> build TCP RST in-place -> ringbuf event -> XDP_TX
```

Synchronous TX does not depend on ringbuf consumption or user-space response execution. If TX construction fails, the packet falls back to `XDP_PASS` and the TX failure counter is incremented.

### XSK TX

Used by `icmp_echo_reply`, `arp_reply`, and `tcp_syn_ack`.

```text
packet -> BPF parse/match -> prepend xsk_meta -> XDP_REDIRECT to XSK
XSK worker -> read xsk_meta -> parse full original packet -> build response -> XSK_TX
```

XSK TX is for actions that need full original packet context. Ringbuf must not be used to carry packet fields required for response construction.

`xsk_tx` dataplane statistics and `verdict=xsk` observation events mean BPF
successfully submitted the packet to XSK. They do not mean the user-space
response packet was transmitted.

`tcp_syn_ack` is guarded in BPF and only redirects initial SYN packets. SYN
packets that also carry ACK, RST, or FIN pass without XSK redirect.

The current user-space response builders reject VLAN-tagged frames until VLAN
tag preservation is implemented for response TX. The `tcp_syn_ack` builder also
rejects SYN payloads until TCP Fast Open style payload ACK semantics are
implemented.

## XSK Metadata

BPF prepends an 8-byte metadata header before redirecting a frame to XSK:

```text
u32 rule_id
u16 action
u16 reserved
```

`xsk_meta` carries only dispatch metadata. The XSK worker must parse the redirected original packet for MAC, ARP, ICMP, TCP sequence, ACK, option, and payload context.

The XSK worker must strip these 8 bytes before parsing the original Ethernet
frame. If BPF cannot prepend metadata or cannot submit the redirect, the packet
falls back to `XDP_PASS` and the XSK failure counter is incremented.

## Response Result

Full user-space response results are owned by the XSK worker path. The current
implementation provides a response result model, bounded in-memory result
buffer, and response execution core that records build/TX outcomes. AF_XDP
backend IO still needs to be implemented, but the worker boundary already passes
metadata-prefixed XSK frames to the execution core. The response package also
owns worker-group lifecycle and runtime assembly for queue-scoped XSK backend
factories. Dataplane ringbuf events remain observation events with numeric
verdict codes for `observe`, `tx`, and `xsk`.

Planned response result shape:

```json
{
  "timestamp_ns": 1713000000000000000,
  "rule_id": 1001,
  "action": "icmp_echo_reply",
  "result": "sent",
  "ifindex": 2,
  "rx_queue": 0,
  "sip": 167837962,
  "dip": 3232235796,
  "sport": 52345,
  "dport": 80,
  "ip_proto": 1,
  "error": ""
}
```

`sip` and `dip` are IPv4 addresses stored as host-order `u32` values, matching
the dataplane event ABI representation.

Result values:

| Result | Semantics |
|--------|-----------|
| `sent` | Response frame was transmitted |
| `skipped` | Worker intentionally skipped response execution |
| `failed` | Worker attempted execution and failed |

The in-memory result buffer is a local process buffer. It stores the newest
records up to its configured capacity and evicts the oldest records when full.
Durable response result storage and management-plane query APIs are planned
separate changes.

## Runtime Configuration

The top-level `response` config block is parsed by the config layer. Response
execution remains disabled unless `response.enabled` is true. Worker queues
default to queue `0` when omitted, and the local result buffer defaults to
capacity `1024` when `result_buffer_size` is omitted or zero.

```yaml
response:
  enabled: false
  queues: [0]
  result_buffer_size: 1024
  hardware_addr: ""
  tcp_seq: 1
```

`hardware_addr` is reserved for ARP reply source hardware address selection.
`tcp_seq` is reserved for the TCP SYN-ACK response sequence seed. AF_XDP socket
startup and response runtime wiring are still planned.

## Module Boundaries

- The control plane validates `response.action`.
- The dataplane sync path encodes `response.action` into the numeric BPF action code.
- BPF owns `none`, `alert`, and `tcp_reset` execution.
- BPF only redirects XSK TX actions and writes `xsk_meta`; it does not build complex spoof responses.
- The XSK worker owns user-space TX response construction and result reporting.
- The XSK worker must not decide whether a response should happen; that decision comes from the matched rule action.
- Ringbuf is an observation channel, not a packet construction data channel.

## Related Contracts

- Rule action model: `RULES.md`
- Event structure: `EVENTS.md`
- Module boundaries: `MODULES.md`
