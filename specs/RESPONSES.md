# Responses

This document defines the active response action contract and execution paths.

Rules reference responses through `response.action`. The control plane validates
the action name. The dataplane sync path encodes it as the action code defined
in `RULES.md`.

## Action Contract

| Action | Code | Path | Current Status | Semantics |
|--------|------|------|----------------|-----------|
| `none` | `0` | dataplane pass | active | Match silently; final original-packet disposition is `XDP_PASS` or `XDP_DROP` by `dataplane.ingress_verdict` |
| `alert` | `1` | dataplane observe | active | Emit an observation event; final original-packet disposition is `XDP_PASS` or `XDP_DROP` by `dataplane.ingress_verdict` |
| `tcp_reset` | `2` | BPF kernel TX | active | Build TCP RST in BPF and send by same-interface `XDP_TX` or configured egress-interface `XDP_REDIRECT` |
| `icmp_echo_reply` | `3` | XSK RX + user-space TX | active | Redirect the original packet to XSK; user space builds ICMP echo reply and transmits through AF_XDP by default or AF_PACKET when egress is configured |
| `arp_reply` | `4` | XSK RX + user-space TX | active | Redirect the original packet to XSK; user space builds ARP reply and transmits through AF_XDP by default or AF_PACKET when egress is configured |
| `tcp_syn_ack` | `5` | XSK RX + user-space TX | Linux AF_XDP socket implemented, integration pending | Redirect the original packet to XSK; user space builds TCP SYN-ACK and transmits through AF_XDP by default or AF_PACKET when egress is configured |
| `icmp_port_unreachable` | `6` | BPF kernel TX | active | Build ICMP destination-unreachable / port-unreachable in BPF and send by same-interface `XDP_TX` or configured egress-interface `XDP_REDIRECT` |
| `udp_echo_reply` | `7` | XSK RX + user-space TX | active | Redirect the original packet to XSK; user space swaps Ethernet/IP/UDP source and destination fields and echoes the UDP payload |
| `dns_refused` | `8` | XSK RX + user-space TX | active | Redirect the original packet to XSK; user space returns a UDP DNS response with `RCODE=REFUSED` and the original question copied back |
| `icmp_host_unreachable` | `9` | BPF kernel TX | active | Build ICMP destination-unreachable / host-unreachable in BPF and send by same-interface `XDP_TX` or configured egress-interface `XDP_REDIRECT` |
| `icmp_admin_prohibited` | `10` | BPF kernel TX | active | Build ICMP destination-unreachable / administratively-prohibited in BPF and send by same-interface `XDP_TX` or configured egress-interface `XDP_REDIRECT` |

Action names are stable snake-case API values. Numeric codes are the dataplane
ABI and must stay synchronized with BPF definitions.

## Execution Paths

### Dataplane Pass

Used by `none`.

```text
packet -> BPF parse/match -> XDP_PASS or XDP_DROP by dataplane.ingress_verdict
```

No response packet is generated and no observation event is required.

### Dataplane Observe

Used by `alert`.

```text
packet -> BPF parse/match -> ringbuf event -> XDP_PASS or XDP_DROP by dataplane.ingress_verdict
```

The ringbuf event is only for observation, statistics, and audit.

### BPF Kernel TX

Used by `tcp_reset`, `icmp_port_unreachable`, `icmp_host_unreachable`, and `icmp_admin_prohibited`.

```text
packet -> BPF parse/match -> build response in-place -> ringbuf event -> XDP_TX
packet -> BPF parse/match -> build response in-place -> bpf_fib_lookup -> ringbuf event -> XDP_REDIRECT
```

Kernel TX does not depend on ringbuf consumption or user-space response
execution. Same-interface mode returns `XDP_TX`. Redirect mode uses
`bpf_fib_lookup` with the configured egress interface and returns
`XDP_REDIRECT` after updating Ethernet source and destination addresses.

Redirect mode supports two VLAN policies for a single 802.1Q tag:

- `preserve`: keep the original VLAN tag, for trunk egress ports
- `access`: strip the VLAN tag before redirecting, for access egress ports

If TX construction, VLAN stripping, FIB lookup, or redirect preparation fails,
the dataplane increments the corresponding failure counter and returns the
configured failure verdict: `XDP_PASS` or `XDP_DROP`.

### XSK RX + User-Space TX

Used by `icmp_echo_reply`, `arp_reply`, `tcp_syn_ack`, `udp_echo_reply`, and `dns_refused`.

```text
packet -> BPF parse/match -> write xsk_meta into XDP metadata -> XDP_REDIRECT to XSK
AF_XDP backend -> expose xsk_meta as an 8-byte prefix to the worker
XSK worker -> read xsk_meta -> parse full original packet -> build response -> AF_XDP TX or AF_PACKET TX
```

XSK redirect is for actions that need full original packet context. Ringbuf
must not be used to carry packet fields required for response construction.

`xsk_redirected` dataplane statistics and `verdict=xsk` observation events mean
BPF successfully submitted the original packet to XSK. They do not mean the
user-space response packet was transmitted.

`tcp_syn_ack` is guarded in BPF and only redirects initial SYN packets. SYN
packets that also carry ACK, RST, or FIN fall back to
`dataplane.ingress_verdict` without XSK redirect.

User-space response actions share one sending abstraction with two transport
modes:

- `AF_XDP`: default mode when `egress.interface: ""`; the worker transmits
  built Ethernet frames through the queue-local AF_XDP socket
- `AF_PACKET`: enabled when `egress.interface` is non-empty; the worker still
  receives and parses packets from ingress XSK. IPv4 response actions transmit
  through a raw IPv4 socket bound to the configured interface so the kernel can
  resolve next-hop routing and L2 neighbors on that egress path. Non-IP
  actions such as `arp_reply` continue to transmit raw Ethernet frames through
  an AF_PACKET socket bound to the configured interface.

The current same-interface response builders reject VLAN-tagged frames until
VLAN tag preservation is implemented for user-space TX. The `tcp_syn_ack`
builder also rejects SYN payloads until TCP Fast Open style payload ACK
semantics are implemented.

`udp_echo_reply` preserves the original UDP payload unchanged and rebuilds the
IPv4 and UDP checksums on the swapped tuple.

`dns_refused` v1 supports IPv4 UDP DNS queries only. It requires a standard
query with exactly one question, returns `QR=1` and `RCODE=REFUSED`, copies the
question section back unchanged, and clears answer, authority, and additional
sections. EDNS OPT and other additional records are not preserved in v1.

## XSK Metadata

BPF writes an 8-byte metadata header into the XDP metadata area before
redirecting a frame to XSK:

```text
u32 rule_id
u16 action
u16 reserved
```

`xsk_meta` carries only dispatch metadata. The AF_XDP backend reads it from
reserved XDP metadata headroom and exposes it as an 8-byte prefix to the XSK
worker. The worker must parse the redirected original packet for MAC, ARP,
ICMP, TCP sequence, ACK, option, and payload context.

The XSK worker must strip these 8 bytes before parsing the original Ethernet
frame. If BPF cannot allocate metadata or cannot submit the redirect, the
packet falls back to `dataplane.ingress_verdict` and the XSK redirect failure
counter is incremented.

## Response Result

Full user-space response results are owned by the XSK worker path. The current
implementation provides a response result model, bounded in-memory result
buffer, response execution core, worker lifecycle, runtime assembly, Linux
AF_XDP socket IO, and runtime TX counters. Dataplane ringbuf events remain
observation events with numeric verdict codes for `observe`, `tx`, `xsk`, and
`redirect_tx`.

Current response result shape:

```json
{
  "timestamp_ns": 1713000000000000000,
  "rule_id": 1001,
  "action": "icmp_echo_reply",
  "result": "sent",
  "tx_backend": "afxdp",
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

`tx_backend` values:

| Value | Meaning |
|-------|---------|
| `afxdp` | User-space TX used the AF_XDP backend |
| `afpacket` | User-space TX used the AF_PACKET backend |

The in-memory result buffer is a local process buffer. It stores the newest
records up to its configured capacity and evicts the oldest records when full.
Durable response result storage and management-plane query APIs are planned
separate changes.

## Response TX Stats

User-space response runtime keeps its own monotonic counters. These counters
are independent from the in-memory result buffer and are the `/stats` source
for the `response_tx` stage.

Public counter contract:

- `response_sent`
- `response_failed`
- `afxdp_tx`
- `afxdp_tx_failed`
- `afpacket_tx`
- `afpacket_tx_failed`

Constraints:

- `response_sent = afxdp_tx + afpacket_tx`
- `response_failed = afxdp_tx_failed + afpacket_tx_failed`

Build failures and transport send failures are both attributed to the current
sender backend. `ResultSkipped` is still valid in the result buffer model but
is not part of the current `/stats` contract.

## Runtime Configuration

The config layer parses a top-level `egress` block plus the nested
`response.runtime` and `response.actions` blocks. User-space response execution
remains disabled unless `response.runtime.enabled` is true. Worker queues
default to queue `0` when omitted. If `dataplane.combined_channels` is configured
to a positive value and `response.runtime.queues` is omitted, the runtime
derives sequential worker queues `0..combined_channels-1`. The local result
buffer defaults to capacity `1024` when
`response.runtime.result_buffer_size` is omitted or zero.

```yaml
dataplane:
  interface: eth0
  combined_channels: 0

egress:
  interface: ""
  vlan_mode: preserve
  failure_verdict: pass

response:
  runtime:
    enabled: false
    queues: [0]
    result_buffer_size: 1024
    afxdp:
      frame_size: 4096
      frame_count: 4096
      fill_ring_size: 2048
      completion_ring_size: 2048
      rx_ring_size: 2048
      tx_ring_size: 2048
      tx_frame_reserve: 256
  actions:
    arp_reply:
      hardware_addr: ""
    tcp_syn_ack:
      tcp_seq: 1
```

`egress` config fields:

`dataplane` config also includes:

- `ingress_verdict`: global ingress disposition for packets not explicitly
  consumed by kernel TX or XSK redirect. `pass` preserves current host-stack
  delivery behavior. `drop` is recommended for dedicated mirror-port
  deployments.
- `combined_channels`: optional NIC combined-channel target applied by the
  service at startup on the ingress interface. `0` keeps the host's current
  queue layout.
- `interface`: shared TX egress policy. `""` keeps same-interface TX. For
  `tcp_reset`, a non-empty interface name enables BPF redirect TX. For
  user-space actions, a non-empty interface name enables AF_PACKET TX after the
  packet is received from ingress XSK.
- `vlan_mode`: shared TX VLAN policy for actions that support alternate egress
  transmission, starting with `tcp_reset`, `icmp_port_unreachable`,
  `icmp_echo_reply`, and `arp_reply`.
- `failure_verdict`: shared TX failure policy surface for actions that support
  alternate egress transmission, starting with `tcp_reset`,
  `icmp_port_unreachable`, `icmp_echo_reply`, and `arp_reply`.

`response.actions.arp_reply.hardware_addr` selects the ARP reply source
hardware address when configured.
