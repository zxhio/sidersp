#ifndef SIDERSP_BPF_MATCH_H
#define SIDERSP_BPF_MATCH_H

#include <bpf/bpf_endian.h>

#include "maps.h"

#define FLOW_CACHE_STABLE_CONDS (COND_PROTO_TCP | COND_PROTO_UDP | \
                                 COND_SRC_PREFIX | COND_DST_PREFIX | \
                                 COND_SRC_PORT | COND_DST_PORT)

static __always_inline int apply_u16_index(void *map, __u16 key, mask_t *candidates)
{
    const mask_t *m = bpf_map_lookup_elem(map, &key);

    if (!m)
        return 0;

    mask_and(candidates, m);
    return 1;
}

static __always_inline int apply_ipv4_lpm_index(void *map, __be32 addr, mask_t *candidates)
{
    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = addr,
    };
    const mask_t *m = bpf_map_lookup_elem(map, &key);

    /*
     * This relies on the LPM trie value being a cumulative candidate mask
     * for the longest returned prefix entry. Data plane does a single LPM
     * lookup here; control-plane index building must pre-merge shorter
     * covering prefixes into more specific entries.
     */
    if (!m)
        return 0;

    mask_and(candidates, m);
    return 1;
}

static __always_inline int rule_matches(const struct rule_meta *rule, __u32 pkt_conds)
{
    return (pkt_conds & rule->required_mask) == rule->required_mask;
}

static int pick_best_rule(const mask_t *candidates, __u32 pkt_conds,
                          struct rule_meta *best_rule)
{
    __u32 group;

    #pragma clang loop unroll(disable)
    for (group = 0; group < RULE_GROUPS; group++) {
        __u64 word = candidates->bits[group];
        __u32 bit;

        if (!word)
            continue;

        #pragma clang loop unroll(disable)
        for (bit = 0; bit < RULES_PER_GROUP; bit++) {
            __u32 slot;
            const struct rule_meta *rule;

            if (!(word & (1ULL << bit)))
                continue;

            slot = group * RULES_PER_GROUP + bit;
            rule = bpf_map_lookup_elem(&rule_index_map, &slot);
            if (!rule)
                continue;
            if (!rule_matches(rule, pkt_conds))
                continue;
            /* First match = best priority (dataplane sync pre-sorted). */
            *best_rule = *rule;
            return 1;
        }
    }

    return 0;
}

static __always_inline int is_flow_cacheable_action(__u16 action)
{
    switch (action) {
    case ACTION_TCP_RESET:
    case ACTION_ICMP_PORT_UNREACHABLE:
    case ACTION_ICMP_HOST_UNREACHABLE:
    case ACTION_ICMP_ADMIN_PROHIBITED:
        return 1;
    default:
        return 0;
    }
}

static __always_inline int is_flow_cacheable_rule(const struct rule_meta *rule)
{
    if (!is_flow_cacheable_action(rule->action))
        return 0;
    return (rule->required_mask & ~FLOW_CACHE_STABLE_CONDS) == 0;
}

static __always_inline int build_flow_cache_key(const struct pkt_ctx *ctx,
                                                struct flow_cache_key *key)
{
    if (ctx->ip_proto != IPPROTO_TCP && ctx->ip_proto != IPPROTO_UDP)
        return 0;

    key->saddr = ctx->saddr;
    key->daddr = ctx->daddr;
    key->sport = bpf_htons(ctx->sport);
    key->dport = bpf_htons(ctx->dport);
    key->ip_proto = ctx->ip_proto;
    key->reserved[0] = 0;
    key->reserved[1] = 0;
    key->reserved[2] = 0;
    return 1;
}

static __always_inline int lookup_flow_cache(const struct pkt_ctx *ctx,
                                             struct rule_meta *rule)
{
    const struct flow_cache_entry *entry;
    struct flow_cache_key key = {};

    if (!build_flow_cache_key(ctx, &key))
        return 0;

    entry = bpf_map_lookup_elem(&flow_cache_map, &key);
    if (!entry)
        return 0;

    if (entry->expires_at_ns <= bpf_ktime_get_ns()) {
        bpf_map_delete_elem(&flow_cache_map, &key);
        return 0;
    }

    rule->rule_id = entry->rule_id;
    rule->required_mask = 0;
    rule->action = entry->action;
    rule->flags = 0;
    return 1;
}

static __always_inline void store_flow_cache(const struct pkt_ctx *ctx,
                                             const struct rule_meta *rule)
{
    struct flow_cache_key key = {};
    struct flow_cache_entry entry = {};

    if (!is_flow_cacheable_rule(rule))
        return;
    if (!build_flow_cache_key(ctx, &key))
        return;

    entry.expires_at_ns = bpf_ktime_get_ns() + FLOW_CACHE_TTL_NS;
    entry.rule_id = rule->rule_id;
    entry.action = rule->action;
    entry.reserved = 0;

    bpf_map_update_elem(&flow_cache_map, &key, &entry, BPF_ANY);
}

#endif
