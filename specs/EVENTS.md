# Events

This document defines the dataplane observation event contract.

Events are emitted by BPF through ringbuf after a rule match produces an observable outcome. Events are used for status display, statistics, and audit. They are not a packet construction data channel.

## Event Scope

- `alert` emits an observation event before applying `dataplane.ingress_verdict`.
- `tcp_reset` and `icmp_port_unreachable` emit an event only after successful
  BPF kernel TX. They return `XDP_TX` for same-interface TX or `XDP_REDIRECT`
  for configured egress interface TX.
- XSK TX actions emit an event only after successful `XDP_REDIRECT` to XSK.
- `none` does not require an event.
- XSK worker response results are separate from dataplane observation events; see `RESPONSES.md`.

## Ringbuf ABI

The BPF event ABI is a packed 32-byte structure:

```text
offset  size  field
0       8     timestamp_ns
8       4     rule_id
12      4     pkt_conds
16      4     sip
20      4     dip
24      2     action
26      2     sport
28      2     dport
30      1     verdict
31      1     ip_proto
```

All multi-byte fields are encoded in little-endian ringbuf memory. `sip` and `dip` are IPv4 addresses stored as host-order `u32` values after BPF converts them from network byte order.

## Logical Event Shape

Consumers may expose the decoded event in this logical shape:

```json
{
  "timestamp_ns": 1713000000000000000,
  "rule_id": 1001,
  "pkt_conds": 131,
  "action": "tcp_reset",
  "verdict": "tx",
  "sip": "10.1.2.3",
  "dip": "192.168.1.20",
  "sport": 52345,
  "dport": 80,
  "ip_proto": 6
}
```

The ringbuf ABI stores `action` and `verdict` as numeric codes. Presentation layers may map them to stable names.

## Fields

| Field | Type | Semantics |
|-------|------|-----------|
| `timestamp_ns` | `u64` | BPF monotonic timestamp from `bpf_ktime_get_ns()` |
| `rule_id` | `u32` | Matched rule ID |
| `pkt_conds` | `u32` | Packet condition bitmask extracted by the dataplane |
| `sip` | `u32` | Source IPv4 address, host-order integer in the ABI |
| `dip` | `u32` | Destination IPv4 address, host-order integer in the ABI |
| `action` | `u16` | Dataplane action code defined in `RULES.md` |
| `sport` | `u16` | Source L4 port when available, otherwise `0` |
| `dport` | `u16` | Destination L4 port when available, otherwise `0` |
| `verdict` | `u8` | Dataplane business verdict code |
| `ip_proto` | `u8` | IP protocol number when available |

## Verdict Codes

| Code | Name | Semantics |
|------|------|-----------|
| `0` | `observe` | Observation event emitted before final `dataplane.ingress_verdict` is applied to the original packet |
| `1` | `tx` | BPF same-interface TX succeeded |
| `2` | `xsk` | Packet was submitted to XSK; user-space response execution is tracked separately |
| `3` | `redirect_tx` | Packet was submitted to a configured egress interface with `XDP_REDIRECT` |

These names describe platform-level outcomes, not raw Linux XDP return
constants. `redirect_tx` means BPF submitted the redirect; it does not prove the
egress NIC, switch, or destination host accepted the packet.

## Packet Conditions

`pkt_conds` is a bitmask of dataplane-extracted packet properties. It is matched against each compiled rule's `required_mask`.

| Bit | Name | Semantics |
|-----|------|-----------|
| `0` | `PROTO_TCP` | TCP packet |
| `1` | `PROTO_UDP` | UDP packet |
| `2` | `PROTO_ICMP` | ICMP packet |
| `3` | `PROTO_ARP` | ARP packet |
| `4` | `VLAN` | VLAN condition matched an indexed rule value |
| `5` | `SRC_PREFIX` | Source IPv4 prefix condition matched |
| `6` | `DST_PREFIX` | Destination IPv4 prefix condition matched |
| `7` | `SRC_PORT` | Source port condition matched |
| `8` | `DST_PORT` | Destination port condition matched |
| `9` | `TCP_SYN` | TCP SYN flag set |
| `10` | `TCP_ACK` | TCP ACK flag set |
| `11` | `TCP_RST` | TCP RST flag set |
| `12` | `TCP_FIN` | TCP FIN flag set |
| `13` | `TCP_PSH` | TCP PSH flag set |
| `14` | `ICMP_ECHO_REQUEST` | ICMP echo request |
| `15` | `ICMP_ECHO_REPLY` | ICMP echo reply |
| `16` | `ARP_REQUEST` | ARP request |
| `17` | `ARP_REPLY` | ARP reply |
| `18` | `L4_PAYLOAD` | L4 payload is present |

## Boundary Rules

- Events are observation records, not full packet snapshots.
- Events must not carry fields required to construct spoof response packets.
- XSK TX response construction must use the original packet delivered through XSK.
- User-space response results are separate records owned by the response/XSK worker path.

## Related Contracts

- Rule action model: `RULES.md`
- Response execution: `RESPONSES.md`
- Module boundaries: `MODULES.md`
