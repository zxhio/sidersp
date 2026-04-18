#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#if 0
/*
 * Deferred protocol / payload support kept for later re-enable.
 *
 * Current XDP build stays on the minimal fast path:
 * Ethernet/VLAN + IPv4 + TCP/UDP + shallow conditions.
 *
 * Re-enable in this order to keep verifier pressure manageable:
 * 1. ARP
 * 2. ICMP
 * 3. IPv6
 * 4. HTTP payload features
 */
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

struct arp_eth_ipv4 {
    __u8 sha[ETH_ALEN];
    __u8 sip[4];
    __u8 tha[ETH_ALEN];
    __u8 dip[4];
};
#endif

struct vlan_hdr {
    __be16 tci;
    __be16 encapsulated_proto;
};

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);

    if (val)
        (*val)++;
}

#if 0
/* Deferred HTTP payload feature helpers. */
static __always_inline int payload_prefix_eq(const struct pkt_ctx *ctx, void *data_end,
                                             const char *lit, __u32 lit_len)
{
    const char *p = ctx->payload;
    __u32 i;

    if (!p || ctx->payload_len < lit_len)
        return 0;
    if ((const void *)(p + lit_len) > data_end)
        return 0;

    for (i = 0; i < 8; i++) {
        if (i >= lit_len)
            break;
        if (p[i] != lit[i])
            return 0;
    }

    return 1;
}

static __always_inline int payload_eq_at(const char *p, void *data_end, __u32 off,
                                         const char *lit, __u32 lit_len)
{
    __u32 i;

    if ((const void *)(p + off + lit_len) > data_end)
        return 0;

    for (i = 0; i < 8; i++) {
        if (i >= lit_len)
            break;
        if (p[off + i] != lit[i])
            return 0;
    }

    return 1;
}

static __always_inline int payload_contains_http11(const struct pkt_ctx *ctx, void *data_end)
{
    const char *p = ctx->payload;
    const char *lit = "HTTP/1.1";
    __u32 max_scan = 24;
    __u32 off;

    if (!p || ctx->payload_len < 8)
        return 0;
    if (payload_prefix_eq(ctx, data_end, lit, 8))
        return 1;

    if (ctx->payload_len < max_scan + 8)
        max_scan = ctx->payload_len - 8;

#pragma clang loop unroll(disable)
    for (off = 0; off < 24; off++) {
        if (off > max_scan)
            break;
        if (payload_eq_at(p, data_end, off, lit, 8))
            return 1;
    }

    return 0;
}
#endif

static __u32 detect_conditions(const struct pkt_ctx *ctx)
{
    __u32 pkt_conds = 0;

    if (ctx->vlan_id != VLAN_ID_NONE)
        pkt_conds |= COND_VLAN;
    if (ctx->sport != 0)
        pkt_conds |= COND_SRC_PORT;
    if (ctx->dport != 0)
        pkt_conds |= COND_DST_PORT;
    if (ctx->tcp_flags & TCP_FLAG_SYN)
        pkt_conds |= COND_TCP_SYN;

#if 0
    /* Deferred HTTP payload-derived conditions. */
    if (payload_prefix_eq(ctx, data_end, "GET ", 4) ||
        payload_prefix_eq(ctx, data_end, "POST ", 5) ||
        payload_prefix_eq(ctx, data_end, "HEAD ", 5))
        pkt_conds |= COND_HTTP_METHOD;

    if (payload_contains_http11(ctx, data_end))
        pkt_conds |= COND_HTTP_11;
#endif

    return pkt_conds;
}

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
            if (!rule || !rule->enabled)
                continue;
            if (!rule_matches(rule, pkt_conds))
                continue;
            /* First match = best priority (control plane pre-sorted). */
            *best_rule = *rule;
            return 1;
        }
    }

    return 0;
}

static __always_inline void emit_event(const struct pkt_ctx *ctx, const struct rule_meta *rule,
                                       __u32 pkt_conds)
{
    struct rule_event *evt = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*evt), 0);

    if (!evt) {
        stat_inc(STAT_RINGBUF_DROPPED);
        return;
    }

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->rule_id = rule->rule_id;
    evt->pkt_conds = pkt_conds;
    evt->action = rule->action;
    evt->sip = ctx->ip_version == 4 ? bpf_ntohl(ctx->saddr) : 0;
    evt->dip = ctx->ip_version == 4 ? bpf_ntohl(ctx->daddr) : 0;
    evt->sport = ctx->sport;
    evt->dport = ctx->dport;
    evt->tcp_flags = ctx->tcp_flags;
    evt->ip_proto = ctx->ip_proto;
    evt->payload_len = ctx->payload_len;

    bpf_ringbuf_submit(evt, 0);
}

static parse_err_t parse_udp(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct udphdr *udp = data;
    void *payload;

    if ((void *)(udp + 1) > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->sport = bpf_ntohs(udp->source);
    ctx->dport = bpf_ntohs(udp->dest);

    payload = udp + 1;
    if (payload > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->payload = payload;
    ctx->payload_len = (__u16)((long)data_end - (long)payload);
    return PARSE_OK;
}

#if 0
/* Deferred ICMP parser support. */
static __always_inline parse_err_t parse_icmp(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct icmphdr *icmp = data;
    void *payload;

    if ((void *)(icmp + 1) > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    payload = icmp + 1;
    if (payload > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->payload = payload;
    ctx->payload_len = (__u16)((long)data_end - (long)payload);
    return PARSE_OK;
}
#endif

static parse_err_t parse_tcp(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct tcphdr *tcp = data;
    __u32 doff_len;
    void *payload;

    if ((void *)(tcp + 1) > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    doff_len = tcp->doff * 4;
    if (doff_len < sizeof(*tcp))
        return PARSE_ERR_TRANSPORT_SHORT;
    if ((void *)tcp + doff_len > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->sport = bpf_ntohs(tcp->source);
    ctx->dport = bpf_ntohs(tcp->dest);
    ctx->tcp_flags =
        (tcp->syn ? TCP_FLAG_SYN : 0) |
        (tcp->ack ? TCP_FLAG_ACK : 0) |
        (tcp->rst ? TCP_FLAG_RST : 0) |
        (tcp->fin ? TCP_FLAG_FIN : 0) |
        (tcp->psh ? TCP_FLAG_PSH : 0);

    payload = (void *)tcp + doff_len;
    if (payload > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->payload = payload;
    ctx->payload_len = (__u16)((long)data_end - (long)payload);
    return PARSE_OK;
}

static parse_err_t parse_ip_l4(struct pkt_ctx *ctx, void *l4,
                               void *data_end, __u8 ip_proto)
{
    ctx->ip_proto = ip_proto;

    switch (ip_proto) {
    case IPPROTO_TCP:
        return parse_tcp(ctx, l4, data_end);
    case IPPROTO_UDP:
        return parse_udp(ctx, l4, data_end);
#if 0
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        return parse_icmp(ctx, l4, data_end);
#endif
    default:
        return PARSE_ERR_UNSUPPORTED_IP_PROTO;
    }
}

static parse_err_t parse_ipv4(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct iphdr *ip = data;
    __u32 ihl_len;
    void *l4;

    if ((void *)(ip + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;

    ihl_len = ip->ihl * 4;
    if (ihl_len < sizeof(*ip))
        return PARSE_ERR_BAD_IPV4;
    if ((void *)ip + ihl_len > data_end)
        return PARSE_ERR_BAD_IPV4;

    ctx->ip_version = 4;
    ctx->saddr = ip->saddr;
    ctx->daddr = ip->daddr;

    l4 = (void *)ip + ihl_len;
    return parse_ip_l4(ctx, l4, data_end, ip->protocol);
}

#if 0
/* Deferred IPv6 / ARP parser support. */
static __always_inline parse_err_t parse_ipv6(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct ipv6hdr *ip6 = data;
    void *l4;

    if ((void *)(ip6 + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;

    ctx->ip_version = 6;
    ctx->saddr6 = ip6->saddr;
    ctx->daddr6 = ip6->daddr;

    l4 = ip6 + 1;
    return parse_ip_l4(ctx, l4, data_end, ip6->nexthdr);
}

static __always_inline parse_err_t parse_arp(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct arphdr *arp = data;
    struct arp_eth_ipv4 *arp4;

    if ((void *)(arp + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;
    if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER))
        return PARSE_ERR_BAD_ARP;
    if (arp->ar_pro != bpf_htons(ETH_P_IP))
        return PARSE_ERR_BAD_ARP;
    if (arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
        return PARSE_ERR_BAD_ARP;

    arp4 = (void *)(arp + 1);
    if ((void *)(arp4 + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;

    ctx->ip_version = 4;
    ctx->ip_proto = 0;
    __builtin_memcpy(&ctx->saddr, arp4->sip, sizeof(ctx->saddr));
    __builtin_memcpy(&ctx->daddr, arp4->dip, sizeof(ctx->daddr));
    return PARSE_OK;
}
#endif

static parse_err_t parse_vlan(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct vlan_hdr *vh = data;
    __u16 encap;

    if ((void *)(vh + 1) > data_end)
        return PARSE_ERR_ETH_SHORT;

    ctx->vlan_id = bpf_ntohs(vh->tci) & 0x0fff;
    encap = bpf_ntohs(vh->encapsulated_proto);
    ctx->eth_proto = encap;

    if (encap == ETH_P_8021Q)
        return PARSE_ERR_BAD_VLAN;

    switch (encap) {
    case ETH_P_IP:
        return parse_ipv4(ctx, vh + 1, data_end);
#if 0
    case ETH_P_IPV6:
        return parse_ipv6(ctx, vh + 1, data_end);
    case ETH_P_ARP:
        return parse_arp(ctx, vh + 1, data_end);
#endif
    default:
        return PARSE_ERR_UNSUPPORTED_ETH_PROTO;
    }
}

static parse_err_t parse_packet(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct ethhdr *eth = data;
    __u16 proto;

    ctx->eth_proto = 0;
    ctx->vlan_id = VLAN_ID_NONE;
    ctx->ip_version = 0;
    ctx->ip_proto = 0;
    ctx->sport = 0;
    ctx->dport = 0;
    ctx->tcp_flags = 0;
    ctx->payload = NULL;
    ctx->payload_len = 0;

    if ((void *)(eth + 1) > data_end)
        return PARSE_ERR_ETH_SHORT;

    proto = bpf_ntohs(eth->h_proto);
    ctx->eth_proto = proto;

    switch (proto) {
    case ETH_P_8021Q:
        return parse_vlan(ctx, eth + 1, data_end);
    case ETH_P_IP:
        return parse_ipv4(ctx, eth + 1, data_end);
#if 0
    case ETH_P_IPV6:
        return parse_ipv6(ctx, eth + 1, data_end);
    case ETH_P_ARP:
        return parse_arp(ctx, eth + 1, data_end);
#endif
    default:
        return PARSE_ERR_UNSUPPORTED_ETH_PROTO;
    }
}

SEC("xdp")
int xdp_sidersp(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct pkt_ctx ctx;
    struct global_cfg *cfg;
    struct rule_meta best_rule = {};
    mask_t candidates;
    __u32 pkt_conds = 0;
    __u32 zero = 0;
    parse_err_t err;

    stat_inc(STAT_RX_PACKETS);

    err = parse_packet(&ctx, data, data_end);
    if (err != PARSE_OK) {
        stat_inc(STAT_PARSE_FAILED);
        return XDP_PASS;
    }

    cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);
    if (!cfg)
        return XDP_PASS;

    mask_copy(&candidates, &cfg->all_enabled_rules);

    if (!apply_u16_index(&vlan_index_map, ctx.vlan_id, &candidates))
        mask_and(&candidates, &cfg->vlan_optional_rules);
    if (!apply_u16_index(&src_port_index_map, ctx.sport, &candidates))
        mask_and(&candidates, &cfg->src_port_optional_rules);
    if (!apply_u16_index(&dst_port_index_map, ctx.dport, &candidates))
        mask_and(&candidates, &cfg->dst_port_optional_rules);

    if (apply_ipv4_lpm_index(&src_prefix_lpm_map, ctx.saddr, &candidates))
        pkt_conds |= COND_SRC_PREFIX;
    else
        mask_and(&candidates, &cfg->src_prefix_optional_rules);

    if (apply_ipv4_lpm_index(&dst_prefix_lpm_map, ctx.daddr, &candidates))
        pkt_conds |= COND_DST_PREFIX;
    else
        mask_and(&candidates, &cfg->dst_prefix_optional_rules);

    if (mask_is_zero(&candidates))
        return XDP_PASS;

    stat_inc(STAT_RULE_CANDIDATES);

    pkt_conds |= detect_conditions(&ctx);

    if (!pick_best_rule(&candidates, pkt_conds, &best_rule))
        return XDP_PASS;

    stat_inc(STAT_MATCHED_RULES);
    emit_event(&ctx, &best_rule, pkt_conds);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
