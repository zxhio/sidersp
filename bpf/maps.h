/*
 * BPF Maps — inverted index + rule storage + event output.
 *
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  rule_index_map       ARRAY<u32, rule_meta>    [1024]    │
 *   │    slot → rule metadata (id, required_mask, action)      │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  global_cfg_map       ARRAY<u32, global_cfg>    [1]      │
 *   │    all_active_rules bitmap (initial candidates)          │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  vlan_index_map       HASH<u16, mask_t>        [4096]    │
 *   │  src_port_index_map   HASH<u16, mask_t>        [4096]    │
 *   │  dst_port_index_map   HASH<u16, mask_t>        [4096]    │
 *   │    key → bitmap of rules matching this key               │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  src_prefix_lpm_map   LPM_TRIE<lpm_key, mask_t>          │
 *   │  dst_prefix_lpm_map   LPM_TRIE<lpm_key, mask_t>          │
 *   │    longest-prefix match → cumulative candidate bitmap    │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  event_ringbuf        RINGBUF    [16 MB]                 │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  stats_map            PERCPU_ARRAY<u32, u64>  [STAT_COUNT]│
 *   │    rx/parse/match/event/drop/tx counters                  │
 *   ├──────────────────────────────────────────────────────────┤
 *   │  xsks_map             XSKMAP<u32, u32>       [64]        │
 *   │    queue_id → XSK fd for XDP_REDIRECT                    │
 *   └──────────────────────────────────────────────────────────┘
 */
#ifndef SIDERSP_BPF_MAPS_H
#define SIDERSP_BPF_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "rule.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULE_SLOTS);
    __type(key, __u32);
    __type(value, struct rule_meta);
} rule_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_cfg);
} global_cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, mask_t);
} src_port_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, mask_t);
} dst_port_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u16);
    __type(value, mask_t);
} vlan_index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    /*
     * Value must be the cumulative candidate mask for the stored prefix.
     *
     * Since LPM lookup only returns the single longest matching entry,
     * control-plane index construction must OR together all rules whose
     * prefixes cover this key, not just the rules declared on the exact
     * stored prefix length.
     */
    __type(value, mask_t);
} src_prefix_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 4096);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct ipv4_lpm_key);
    /* Same cumulative-mask contract as src_prefix_lpm_map. */
    __type(value, mask_t);
} dst_prefix_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

#endif
