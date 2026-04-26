# BPF Data Plane Specification

This document specifies the behavior of the XDP BPF program (`bpf/prog.c`):
packet parsing, rule matching, action handling, event output, and
map layouts.
All tests and implementations must conform to this specification.

## 1. Supported Packet Types

All packets increment `rx_packets` and return `XDP_PASS`. Whether `parse_failed` is
incremented depends on the parse result.

| EtherType | Protocol | parse_failed | Details |
|-----------|----------|:------------:|---------|
| IPv4 (0x0800) | TCP | no | Full parse: ports, flags, payload |
| IPv4 (0x0800) | UDP | no | Full parse: ports, payload |
| IPv4 (0x0800) | ICMP | no | Header and payload length parse only |
| IPv4 (0x0800) | Other | **yes** | `PARSE_ERR_UNSUPPORTED_IP_PROTO` |
| 802.1Q → IPv4 | TCP/UDP/ICMP | no | Single VLAN tag only |
| ARP (0x0806) | IPv4 over Ethernet | no | Sender/target IPv4 addresses parsed |
| 802.1Q → 802.1Q (0x8100) | — | **yes** | `PARSE_ERR_BAD_VLAN` (inner EtherType 0x8100 = double-tagged) |
| 802.1AD (0x88a8) | — | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` (not recognized as VLAN) |
| IPv6 (0x86DD) | Any | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` |
| Other | — | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` |

Truncated or malformed headers (short Ethernet, short IPv4, unsupported IPv4
options, invalid IHL, short TCP, invalid TCP data offset, short UDP, short or
invalid ARP) also increment `parse_failed`.

### Packet Requirements for Matching (no parse_failed)

- Valid Ethernet header (>= 14 bytes)
- For IPv4: IHL must be exactly 5, sufficient
  bytes, and `total_length` must fit within the captured frame. The version field
  is **not** checked — entry is determined by EtherType, so a malformed version
  nibble is not caught.
- IPv4 fragments: the fragment offset field (`ip->frag_off`) is **not** checked.
  Non-first fragments will be parsed as if they carry a TCP/UDP header starting
  at `ip + ihl`, which may produce incorrect ports/flags or a `parse_failed`.
- For TCP: data offset >= 5, sufficient bytes
- For UDP: >= 8 bytes UDP header
- IP protocol must be TCP (6), UDP (17), or ICMP (1)

## 2. XDP Return Values and Response Paths

The program returns one of three outcomes:

| Return | Meaning |
|--------|---------|
| `XDP_PASS` | No match, parse failure, unsupported response path, or configured TX fallback |
| `XDP_DROP` | Configured failure verdict for pure mirror-port deployments |
| `XDP_TX` | `tcp_reset` response was built in-place and transmitted from the ingress interface |
| `XDP_REDIRECT` | Packet was submitted to XSK or to a configured `tcp_reset` egress interface |

Response behavior is fixed by action code plus local runtime configuration.
`tcp_reset` is built in BPF and can use same-interface `XDP_TX` or configured
egress-interface redirect. ICMP echo reply, ARP reply, and TCP SYN-ACK spoof
require full original-packet context and are handled through XSK.

## 3. Rule Matching Semantics

### 3.1 Matching Algorithm

1. Parse packet; if parse fails → increment `parse_failed`, return XDP_PASS
2. Look up `global_cfg_map[0]` for `all_active_rules` bitmap
3. Pre-filter candidates using inverted indexes:
   - VLAN index → `vlan_optional_rules` fallback
   - Source port index → `src_port_optional_rules` fallback
   - Destination port index → `dst_port_optional_rules` fallback
   - Source prefix LPM trie → `src_prefix_optional_rules` fallback
   - Destination prefix LPM trie → `dst_prefix_optional_rules` fallback
   - Protocol is not indexed; `COND_PROTO_*` bits in `required_mask` confirm it
4. If candidates bitmap is all-zero → return XDP_PASS
5. Detect positive packet conditions (set bits in `pkt_conds`)
6. Iterate candidate slots 0..N; first slot where `(pkt_conds & required_mask) == required_mask` wins
7. Execute the action behavior fixed in BPF code
8. For `ACTION_TCP_RESET`: rewrite packet as TCP RST and return `XDP_TX` or
   `XDP_REDIRECT` according to `tx_config_map`
9. For spoof actions: write `xsk_meta` into XDP metadata and submit the original packet to `xsks_map[ctx->rx_queue_index]`
10. If XSK metadata allocation or redirect fails, increment `xsk_redirect_failed` plus the detailed XSK failure counter, and return `XDP_PASS`
11. Emit optional ringbuf observation event

### 3.2 Condition Bits

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | COND_PROTO_TCP | IPv4 protocol is TCP |
| 1 | COND_PROTO_UDP | IPv4 protocol is UDP |
| 2 | COND_PROTO_ICMP | IPv4 protocol is ICMP |
| 3 | COND_PROTO_ARP | EtherType is ARP |
| 4 | COND_VLAN | Packet carries a VLAN tag (vlan_id != 0xFFFF) |
| 5 | COND_SRC_PREFIX | Source IPv4 matched a source prefix condition |
| 6 | COND_DST_PREFIX | Destination IPv4 matched a destination prefix condition |
| 7 | COND_SRC_PORT | TCP/UDP source port matched a source port condition |
| 8 | COND_DST_PORT | TCP/UDP destination port matched a destination port condition |
| 9 | COND_TCP_SYN | TCP SYN flag is set |
| 10 | COND_TCP_ACK | TCP ACK flag is set |
| 11 | COND_TCP_RST | TCP RST flag is set |
| 12 | COND_TCP_FIN | TCP FIN flag is set |
| 13 | COND_TCP_PSH | TCP PSH flag is set |
| 14 | COND_ICMP_ECHO_REQUEST | ICMP type=8 and code=0 |
| 15 | COND_ICMP_ECHO_REPLY | ICMP type=0 and code=0 |
| 16 | COND_ARP_REQUEST | ARP operation is request |
| 17 | COND_ARP_REPLY | ARP operation is reply |
| 18 | COND_L4_PAYLOAD | L4 payload length is greater than zero |

`required_mask` supports positive conditions only. Negative conditions such as
`tcp_flags.ack=false` are rejected by the control plane.

### 3.3 Priority Ordering

The control plane filters disabled rules and validates rule IDs. The dataplane
sync path compiles active rules into slots sorted by `(priority ASC, id ASC)`.
Slot 0 has the highest
priority. First matching slot wins.

`priority` and `enabled` are user-space rule lifecycle fields and are not stored
in `rule_meta`.

### 3.4 Wildcard / Optional Conditions

When a rule does not specify a condition (e.g., no `src_prefixes`), that
condition is treated as "match anything". The dataplane compiler marks such rules
in the corresponding `*_optional_rules` bitmap so they survive the pre-filter
stage when no index entry matches. Optional rules are also included in every
concrete index entry's mask, so they are preserved regardless of whether the
index lookup hits or misses.

### 3.5 LPM Trie Semantics

The BPF LPM trie (`BPF_MAP_TYPE_LPM_TRIE`) performs a single longest-prefix-match
lookup using `/32` as the lookup key. Each prefix entry's value is a cumulative
bitmap: the dataplane compiler includes every rule whose **broader** prefix covers that
entry's network address. For example, a `/24` entry's mask includes rules with
matching `/24`, `/23`, `/16`, or `/0` prefixes — all prefixes that contain the
`/24` subnet.

### 3.6 Rule Sync Responsibilities

The control plane performs high-level validation before dataplane sync:

- Filter out `enabled=false` rules.
- Reject duplicate rule IDs.
- Reject unsupported negative match conditions.
- Reject unsupported match fields and action names.

The dataplane sync path compiles active rules before writing BPF maps:

- Sort active rules by `(priority ASC, id ASC)`.
- Compile concrete values into index maps.
- Compile positive semantic requirements into `required_mask`.

The BPF program only consumes active, normalized rules.

## 4. Ringbuf Event Format

Ringbuf events are observation records only. They are not used as the packet
data channel for TX response construction. XSK TX handlers receive
the full original packet through XSK.

Each matched packet may attempt to produce one event in the `event_ringbuf` map.
`matched_rules` is incremented before the action path is selected.
If the event reserve fails, `ringbuf_dropped` is incremented instead and no event
is delivered.

### Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | timestamp_ns | `bpf_ktime_get_ns()` — monotonic nanoseconds |
| 8 | 4 | rule_id | Matched rule's ID (from `rule_meta.rule_id`) |
| 12 | 4 | pkt_conds | Packet condition bitmask |
| 16 | 4 | sip | Source IPv4 address, **host byte order** (bpf_ntohl) |
| 20 | 4 | dip | Destination IPv4 address, **host byte order** (bpf_ntohl) |
| 24 | 2 | action | Action code (see §6) |
| 26 | 2 | sport | Source port, **host byte order** (bpf_ntohs) |
| 28 | 2 | dport | Destination port, **host byte order** (bpf_ntohs) |
| 30 | 1 | verdict | Data-plane verdict: observe / tx / xsk |
| 31 | 1 | ip_proto | IP protocol: 1=ICMP, 6=TCP, 17=UDP |

### Guarantees

- No packet payload or packet snapshot is stored in the ringbuf event
- No event is required for unmatched packets
- `matched_rules` may be greater than actual delivered events when ringbuf is full
- `sip`/`dip` are stored in **host byte order** (not network byte order)
- `sport`/`dport` are stored in **host byte order**
- `ifindex`, `rx_queue`, `tcp_flags`, and `payload_len` are excluded from the 32-byte event format

## 5. BPF Map Layouts

### `rule_index_map` — ARRAY (512 entries)

Key: `uint32` slot index (0..511)
Value: `rule_meta`

| Field | Type | Description |
|-------|------|-------------|
| rule_id | uint32 | Rule identifier |
| required_mask | uint32 | Bitmask of required condition bits |
| action | uint16 | Action code (see §6) |
| flags | uint8 | Per-rule action flags; written as 0 |

`rule_meta` intentionally does not contain `enabled`, `priority`, or
`forbidden_mask`.

C layout:

```c
struct rule_meta {
    __u32 rule_id;
    __u32 required_mask;
    __u16 action;
    __u8  flags;
};
```

### `global_cfg_map` — ARRAY (1 entry)

Key: `uint32` (always 0)
Value: `global_cfg`

| Field | Type | Description |
|-------|------|-------------|
| all_active_rules | mask_t (64 bytes) | Bitmap of all active compiled rule slots |
| vlan_optional_rules | mask_t | Rules without VLAN condition |
| src_port_optional_rules | mask_t | Rules without src port condition |
| dst_port_optional_rules | mask_t | Rules without dst port condition |
| src_prefix_optional_rules | mask_t | Rules without src prefix condition |
| dst_prefix_optional_rules | mask_t | Rules without dst prefix condition |

### `mask_t` — Bitmap (64 bytes)

8 × uint64 words = 512 bits. Bit N set → rule at slot N is a candidate.

### Index Maps (HASH)

`vlan_index_map`, `src_port_index_map`, `dst_port_index_map`

Key: `uint16` (VLAN ID / port number)
Value: `mask_t` — bitmap of candidate rule slots

Sentinel values:
- VLAN: `0xFFFF` (VLAN_ID_NONE) maps to rules without VLAN condition
- Ports: `0` maps to rules without port condition

### Prefix Index Maps (LPM_TRIE)

`src_prefix_lpm_map`, `dst_prefix_lpm_map`

Key: `ipv4_lpm_key` — `{prefixlen: uint32, addr: uint32}`
Value: `mask_t` — cumulative candidate bitmap

The kernel LPM trie compares the raw key bytes directly. The BPF side constructs
the lookup key with `prefixlen=32` and the raw `__be32` value from the packet
(`ctx->saddr` / `ctx->daddr`). Userspace **must** generate map keys via
`makeLPMKey()` — do not hand-construct the byte representation. This function
ensures the `addr` bytes in the Go struct match the network-order bytes the BPF
side will look up, so the kernel's byte-wise prefix comparison works correctly.

### `tx_config_map` — ARRAY

Key `0` stores `tx_config` for BPF-owned response TX:

| Field | Meaning |
|-------|---------|
| `tcp_reset_mode` | `0=xdp_tx`, `1=redirect` |
| `tcp_reset_egress_ifindex` | Egress ifindex for egress-interface mode |
| `tcp_reset_vlan_mode` | `0=preserve`, `1=access` |
| `tcp_reset_failure_verdict` | `0=pass`, `1=drop` |

### `xsks_map` — XSKMAP

Key: `uint32` RX queue index (`ctx->rx_queue_index`)
Value: AF_XDP socket bound to the same queue

XSK TX actions use:

```c
bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS)
```

If no XSK socket is installed for the queue, the fallback action is `XDP_PASS`.

### `stats_map` — PERCPU_ARRAY

| Index | Name | Description |
|-------|------|-------------|
| 0 | rx_packets | Total packets received by XDP program |
| 1 | parse_failed | Packets that failed parsing |
| 2 | rule_candidates | Packets with non-empty candidate set |
| 3 | matched_rules | Packets that matched a rule |
| 4 | ringbuf_dropped | Events dropped due to full ringbuf |
| 5 | xdp_tx | Same-interface TCP reset responses transmitted with `XDP_TX` |
| 6 | xsk_redirected | Packets submitted to XSK for user-space response handling |
| 7 | tx_failed | Failed TCP reset TX attempts |
| 8 | xsk_redirect_failed | Total failed XSK metadata or redirect attempts |
| 9 | xsk_meta_failed | Failed XDP metadata allocation or write attempts before XSK redirect |
| 10 | xsk_map_redirect_failed | Failed `bpf_redirect_map()` attempts for XSK redirect |
| 11 | redirect_tx | TCP reset packets submitted to the configured egress interface |
| 12 | redirect_failed | Failed TCP reset redirect preparation attempts |
| 13 | fib_lookup_failed | Failed `bpf_fib_lookup` attempts for TCP reset redirect |

Values are `per-CPU uint64` — sum across CPUs for total.

## 6. Action Semantics

| Action | Code | Status | Behavior |
|--------|------|--------|----------|
| ACTION_NONE | 0 | active | No response |
| ACTION_ALERT | 1 | active | Observation only |
| ACTION_TCP_RESET | 2 | active | Build TCP RST in BPF and send by configured kernel TX mode |
| ACTION_ICMP_ECHO_REPLY | 3 | BPF redirect active, worker planned | Submit original packet to XSK for user-space TX |
| ACTION_ARP_REPLY | 4 | BPF redirect active, worker planned | Submit original packet to XSK for user-space TX |
| ACTION_TCP_SYN_ACK | 5 | BPF redirect active, worker planned | Submit original packet to XSK for user-space TX |

Rule sync rules:

- The control plane validates action names; there is no separate path field.
- The dataplane sync path compiles action names into numeric action codes.
- `tcp_reset` uses local runtime config to choose same-interface `XDP_TX` or
  egress-interface redirect; spoof actions use XSK and user-space TX.
- Rule YAML uses snake_case action strings; BPF maps use numeric action codes.

## 7. TCP Reset Kernel TX

`ACTION_TCP_RESET` is built in BPF and sent by a configured kernel TX mode.

Supported packet scope:

- Ethernet + IPv4 + TCP
- IPv4 IHL = 5
- TCP data offset >= 5
- No IPv6 and no IPv4 options

Behavior:

1. Swap Ethernet source/destination MAC addresses.
2. Swap IPv4 source/destination addresses.
3. Swap TCP source/destination ports.
4. Set TCP flags to `RST` or `RST|ACK`.
5. Set sequence and acknowledgement numbers according to TCP reset rules.
6. Set IPv4 total length to IPv4 header + TCP header.
7. Recompute IPv4 and TCP checksums.
8. Return `XDP_TX` for same-interface mode, or perform `bpf_fib_lookup` and
   return `XDP_REDIRECT` for egress-interface mode.

Egress-interface mode:

- Uses `tx_config_map[0].tcp_reset_egress_ifindex` as the egress interface.
- Uses `bpf_fib_lookup` to select L2 source/destination MAC addresses.
- Emits `verdict=redirect_tx` and increments `redirect_tx` after redirect is
  submitted.
- Supports single-tag VLAN `preserve` and `access` modes. `access` strips the
  802.1Q header before redirect.
- On VLAN strip, FIB lookup, or redirect preparation failure, increments the
  corresponding failure counter and returns configured `XDP_PASS` or `XDP_DROP`.

Sequence/acknowledgement rule:

- If the original packet has ACK set: `rst.seq = original.ack_seq`, flags = `RST`.
- Otherwise: `rst.ack_seq = original.seq + payload_len + syn_inc + fin_inc`,
  flags = `RST|ACK`.
- If the original packet has RST set: do not send another reset; return
  `XDP_PASS` without incrementing `tx_failed`.

## 8. XSK TX Response

Spoof actions do not require expanding ringbuf events with packet fields. The
BPF path redirects the original packet to AF_XDP; full user-space TX response
construction is planned behind the XSK worker boundary:

```text
BPF match -> write xsk_meta into XDP metadata -> XSK RX
XSK worker -> read xsk_meta -> parse full packet -> build response -> XSK TX
```

User-space reads `rule_id` and `action` from the XDP metadata exposed by the
AF_XDP backend as an 8-byte frame prefix, strips that metadata prefix, and
parses the remaining original Ethernet frame. Response construction uses the
original packet bytes from XSK and does not depend on ringbuf delivery.

`xsk_redirected` and `verdict=xsk` only mean BPF returned `XDP_REDIRECT`. The
response worker reports whether a user-space response was actually sent.

For `ACTION_TCP_SYN_ACK`, BPF redirects only initial SYN packets. Packets with
SYN plus ACK, RST, or FIN are passed without XSK redirect.
