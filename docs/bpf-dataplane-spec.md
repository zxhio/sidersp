# BPF Data Plane Specification

This document specifies the behavior of the XDP BPF program (`bpf/prog.c`):
packet parsing, rule matching, event output, and map layouts.
All tests and implementations must conform to this specification.

## 1. Supported Packet Types

All packets increment `rx_packets` and return `XDP_PASS`. Whether `parse_failed` is
incremented depends on the parse result.

| EtherType | Protocol | parse_failed | Details |
|-----------|----------|:------------:|---------|
| IPv4 (0x0800) | TCP | no | Full parse: ports, flags, payload |
| IPv4 (0x0800) | UDP | no | Full parse: ports, payload |
| IPv4 (0x0800) | Other (ICMP, etc.) | **yes** | `PARSE_ERR_UNSUPPORTED_IP_PROTO` |
| 802.1Q → IPv4 | TCP/UDP | no | Single VLAN tag only |
| 802.1Q → 802.1Q (0x8100) | — | **yes** | `PARSE_ERR_BAD_VLAN` (inner EtherType 0x8100 = double-tagged) |
| 802.1AD (0x88a8) | — | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` (not recognized as VLAN) |
| IPv6 (0x86DD) | Any | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` |
| ARP (0x0806) | — | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` |
| Other | — | **yes** | `PARSE_ERR_UNSUPPORTED_ETH_PROTO` |

Truncated or malformed headers (short Ethernet, short IPv4, invalid IHL, short
TCP, invalid TCP data offset, short UDP) also increment `parse_failed`.

### Packet Requirements for Matching (no parse_failed)

- Valid Ethernet header (>= 14 bytes)
- For IPv4: valid IHL >= 5, sufficient bytes (version field **not** checked —
  entry is determined by EtherType, so a malformed version nibble is not caught).
  Header bounds are checked against captured frame end (`data_end`) only; IP
  total length is not validated.
- IPv4 fragments: the fragment offset field (`ip->frag_off`) is **not** checked.
  Non-first fragments will be parsed as if they carry a TCP/UDP header starting
  at `ip + ihl`, which may produce incorrect ports/flags or a `parse_failed`.
- For TCP: data offset >= 5, sufficient bytes
- For UDP: >= 8 bytes UDP header
- IP protocol must be TCP (6) or UDP (17)

## 2. XDP Return Values

The program **always** returns `XDP_PASS` (value `2`).

Matched packets are reported via ringbuf events but **not** dropped or redirected.
The current `action` field is purely informational — RST/drop actions are for
future implementation.

## 3. Rule Matching Semantics

### 3.1 Matching Algorithm

1. Parse packet; if parse fails → increment `parse_failed`, return XDP_PASS
2. Look up `global_cfg_map[0]` for `all_enabled_rules` bitmap
3. Pre-filter candidates using inverted indexes:
   - VLAN index → `vlan_optional_rules` fallback
   - Source port index → `src_port_optional_rules` fallback
   - Destination port index → `dst_port_optional_rules` fallback
   - Source prefix LPM trie → `src_prefix_optional_rules` fallback
   - Destination prefix LPM trie → `dst_prefix_optional_rules` fallback
4. If candidates bitmap is all-zero → return XDP_PASS
5. Detect packet conditions (set bits in `pkt_conds`)
6. Iterate candidate slots 0..N; first slot where `(pkt_conds & required_mask) == required_mask` wins
7. Emit ringbuf event with matched rule details

### 3.2 Condition Bits

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | COND_VLAN | Packet carries a VLAN tag (vlan_id != 0xFFFF) |
| 1 | COND_SRC_PREFIX | Source IP matched a prefix in the LPM trie |
| 2 | COND_DST_PREFIX | Destination IP matched a prefix in the LPM trie |
| 3 | COND_SRC_PORT | Source port is non-zero |
| 4 | COND_DST_PORT | Destination port is non-zero |
| 5 | COND_HTTP_METHOD | Payload starts with GET/POST/HEAD — accepted by control plane but **never set by BPF**; rules requiring this condition are unmatchable |
| 6 | COND_HTTP_11 | Payload contains "HTTP/1.1" — accepted by control plane but **never set by BPF**; rules requiring this condition are unmatchable |
| 7 | COND_TCP_SYN | TCP SYN flag is set |

### 3.3 Priority Ordering

Rules are compiled into slots sorted by `(priority ASC, id ASC)`.
Slot 0 has the highest priority. First matching slot wins.

### 3.4 Wildcard / Optional Conditions

When a rule does not specify a condition (e.g., no `src_prefixes`), that
condition is treated as "match anything". The control plane marks such rules
in the corresponding `*_optional_rules` bitmap so they survive the pre-filter
stage when no index entry matches. Optional rules are also included in every
concrete index entry's mask, so they are preserved regardless of whether the
index lookup hits or misses.

### 3.5 LPM Trie Semantics

The BPF LPM trie (`BPF_MAP_TYPE_LPM_TRIE`) performs a single longest-prefix-match
lookup using `/32` as the lookup key. Each prefix entry's value is a cumulative
bitmap: the control plane includes every rule whose **broader** prefix covers that
entry's network address. For example, a `/24` entry's mask includes rules with
matching `/24`, `/23`, `/16`, or `/0` prefixes — all prefixes that contain the
`/24` subnet.

## 4. Ringbuf Event Format

Each matched packet attempts to produce one event in the `event_ringbuf` map.
`matched_rules` is incremented before the ringbuf reserve attempt; if the reserve
fails, `ringbuf_dropped` is incremented instead and no event is delivered.

### Structure (36 bytes, packed, little-endian)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | timestamp_ns | `bpf_ktime_get_ns()` — monotonic nanoseconds |
| 8 | 4 | rule_id | Matched rule's ID (from `rule_meta.rule_id`) |
| 12 | 4 | pkt_conds | Packet condition bitmask |
| 16 | 4 | action | Action code: 0=NONE, 1=RST, 2=REPORT (see §6) |
| 20 | 4 | sip | Source IPv4 address, **host byte order** (bpf_ntohl) |
| 24 | 4 | dip | Destination IPv4 address, **host byte order** (bpf_ntohl) |
| 28 | 2 | sport | Source port, **host byte order** (bpf_ntohs) |
| 30 | 2 | dport | Destination port, **host byte order** (bpf_ntohs) |
| 32 | 1 | tcp_flags | TCP flags: SYN=0x02, ACK=0x10, RST=0x04, FIN=0x01, PSH=0x08 |
| 33 | 1 | ip_proto | IP protocol: 6=TCP, 17=UDP |
| 34 | 2 | payload_len | L4 payload bytes after transport header, bounded by IPv4 `total_length`; Ethernet padding/trailing bytes are excluded |

### Guarantees

- No event for unmatched packets
- `matched_rules` may be greater than actual delivered events when ringbuf is full
- `sip`/`dip` are stored in **host byte order** (not network byte order)
- `sport`/`dport` are stored in **host byte order**

## 5. BPF Map Layouts

### `rule_index_map` — ARRAY (1024 entries)

Key: `uint32` slot index (0..1023)
Value: `rule_meta` (20 bytes)

| Field | Type | Description |
|-------|------|-------------|
| rule_id | uint32 | Rule identifier |
| priority | uint32 | Sort key (lower = higher priority) |
| enabled | uint32 | 1 = active, 0 = unused slot |
| required_mask | uint32 | Bitmask of required condition bits |
| action | uint32 | Action code (0=NONE, 1=RST, 2=REPORT) |

### `global_cfg_map` — ARRAY (1 entry)

Key: `uint32` (always 0)
Value: `global_cfg`

| Field | Type | Description |
|-------|------|-------------|
| all_enabled_rules | mask_t (128 bytes) | Bitmap of all active rule slots |
| vlan_optional_rules | mask_t | Rules without VLAN condition |
| src_port_optional_rules | mask_t | Rules without src port condition |
| dst_port_optional_rules | mask_t | Rules without dst port condition |
| src_prefix_optional_rules | mask_t | Rules without src prefix condition |
| dst_prefix_optional_rules | mask_t | Rules without dst prefix condition |

### `mask_t` — Bitmap (128 bytes)

16 × uint64 words = 1024 bits. Bit N set → rule at slot N is a candidate.

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

### `stats_map` — PERCPU_ARRAY (5 entries)

| Index | Name | Description |
|-------|------|-------------|
| 0 | rx_packets | Total packets received by XDP program |
| 1 | parse_failed | Packets that failed parsing |
| 2 | rule_candidates | Packets with non-empty candidate set |
| 3 | matched_rules | Packets that matched a rule |
| 4 | ringbuf_dropped | Events dropped due to full ringbuf |

Values are `per-CPU uint64` — sum across CPUs for total.

## 6. Action Semantics (Current)

| Action | Code | Status | Behavior |
|--------|------|--------|----------|
| NONE | 0 | reserved | Internal default; not configurable via API |
| RST | 1 | **active** | Event recorded; **no actual RST packet sent** (future) |
| REPORT | 2 | reserved | Enum value exists in BPF; not configurable via API |

Currently only RST is accepted by the control plane. All actions are informational
only — the XDP program always returns `XDP_PASS` regardless of the matched action.
