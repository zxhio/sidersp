# XDP Data Plane Flow

```
Packet In
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│  parse_packet()                                              │
│  Ethernet → [VLAN] → IPv4 → TCP/UDP                          │
│  extract: sip, dip, sport, dport, vlan, tcp_flags, payload   │
└──────────────────────┬───────────────────────────────────────┘
                       │ fail → XDP_PASS
                       ▼
┌──────────────────────────────────────────────────────────────┐
│  RULE MATCHING PIPELINE                                      │
│                                                              │
│  1. candidates = global_cfg.all_enabled_rules   (mask)       │
│                         │                                    │
│                         ▼                                    │
│  2. Index pre-filter (AND candidates per dimension)          │
│     ┌────────────────────────────────────────────┐           │
│     │ vlan    ──► vlan_index_map[key]        AND │           │
│     │ sport   ──► src_port_index_map[key]    AND │           │
│     │ dport   ──► dst_port_index_map[key]    AND │           │
│     │ sip     ──► src_prefix_lpm_map[LPM]    AND │           │
│     │ dip     ──► dst_prefix_lpm_map[LPM]    AND │           │
│     └────────────────────────────────────────────┘           │
│                         │                                    │
│              candidates == 0 ? ── YES ──► XDP_PASS           │
│                         │ NO                                 │
│                         ▼                                    │
│  3. detect_conditions() → pkt_conds bitmask                  │
│     VLAN / SRC_PORT / DST_PORT / TCP_SYN /                   │
│     SRC_PREFIX / DST_PREFIX                                  │
│                         │                                    │
│                         ▼                                    │
│  4. Feature pre-filter                                       │
│     candidates &= feature_index_map[each detected bit]       │
│                         │                                    │
│              candidates == 0 ? ── YES ──► XDP_PASS           │
│                         │ NO                                 │
│                         ▼                                    │
│  5. pick_best_rule(candidates, pkt_conds)                    │
│     scan all set bits in candidates bitmap                   │
│     → lookup rule_meta per slot                              │
│     → verify required_mask                                   │
│     → keep smallest priority                                 │
│                         │                                    │
│              no match found ? ── YES ──► XDP_PASS            │
│                         │ found                              │
│                         ▼                                    │
│  6. emit_event() via BPF_RINGBUF                             │
│                                                              │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
                   XDP_PASS
```

## Key Concepts

### mask_t

Fixed-size bitmap backed by an array of `__u64` words. Each bit represents a rule slot; a set bit indicates the rule at that slot is a candidate.

```
  bits[0]     bits[1]           bits[N-1]
  ┌──────────┬──────────┬···┬──────────┐
  │ 64 bits  │ 64 bits  │   │ 64 bits  │
  └──────────┴──────────┴···┴──────────┘
  bit K = 1  →  rule at slot K is a candidate
```

Layout: `slot = group * 64 + bit`, where `group ∈ [0, N)`, `bit ∈ [0, 63)`. Total capacity = `N × 64`.

### Inverted Index Maps

Each index map value is a `mask_t` representing "which rules match this key on this dimension."

### Filtering = AND reduction

Candidates are narrowed by bitwise-AND across each dimension:

```
  all_enabled:  │1 1 1 1 1 1 1 1│
  AND vlan:     │1 0 1 0 1 0 1 0│
  AND port:     │1 0 0 0 0 0 0 0│  ← only slot 0 survives
```

### Final match check

```
(pkt_conds & rule->required_mask) == rule->required_mask
```

`pkt_conds` holds the condition bits detected from the packet. `required_mask` holds all conditions a rule demands. A packet must satisfy **every** condition the rule requires to be considered a match.

### pick_best_rule

After index and feature pre-filtering, the remaining set bits in the candidates bitmap are the potential rule matches. `pick_best_rule` does the following:

```
  for group 0..RULE_GROUPS-1:
    word = candidates.bits[group]
    if word == 0: skip

    for bit 0..63:
      if !(word & (1 << bit)): skip

      slot = group * 64 + bit
      rule = rule_index_map[slot]

      if !rule->enabled: skip
      if (pkt_conds & rule->required_mask) != rule->required_mask: skip

      if rule->priority < best_rule->priority:
        best_rule = rule
```

- Scan all set bits in the candidates bitmap; each set bit corresponds to a rule slot.
- Look up `rule_meta` from `rule_index_map` for each slot.
- Skip disabled rules.
- Verify `required_mask` — this catches combinations that the index alone cannot express.
- Among all verified rules, keep the one with the smallest priority value.

### LPM Trie (prefix matching)

Each prefix dimension performs a single longest-prefix-match lookup. Since LPM Trie only returns the single most specific entry, the control plane must cumulatively merge shorter-prefix rule bitmaps into longer-prefix entries during index construction.

```
  10.0.0.0/8  →  { rule_A }              ← shorter prefix
  10.1.0.0/16 →  { rule_A, rule_B }      ← must include rule_A (cumulative)
```
