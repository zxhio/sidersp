#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "maps.h"

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif
#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif
#ifndef ICMP_PORT_UNREACH
#define ICMP_PORT_UNREACH 3
#endif
#ifndef ICMP_HOST_UNREACH
#define ICMP_HOST_UNREACH 1
#endif
#ifndef ICMP_PKT_FILTERED
#define ICMP_PKT_FILTERED 13
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef VLAN_HLEN
#define VLAN_HLEN 4
#endif

#define TCP_FLAG_TO_COND(flags, flag, cond) \
    (((__u32)((flags) & (flag))) << (__builtin_ctz(cond) - __builtin_ctz(flag)))

struct arp_eth_ipv4 {
    __u8 sha[ETH_ALEN];
    __u8 sip[4];
    __u8 tha[ETH_ALEN];
    __u8 dip[4];
};

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

static __always_inline void emit_event(const struct pkt_ctx *ctx,
                                       const struct rule_meta *rule,
                                       __u32 pkt_conds, __u8 verdict)
{
    struct rule_event *evt = bpf_ringbuf_reserve(&event_ringbuf, sizeof(*evt), 0);

    if (!evt) {
        stat_inc(STAT_RINGBUF_DROPPED);
        return;
    }

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->rule_id = rule->rule_id;
    evt->pkt_conds = pkt_conds;
    evt->sip = bpf_ntohl(ctx->saddr);
    evt->dip = bpf_ntohl(ctx->daddr);
    evt->action = rule->action;
    evt->sport = ctx->sport;
    evt->dport = ctx->dport;
    evt->verdict = verdict;
    evt->ip_proto = ctx->ip_proto;

    bpf_ringbuf_submit(evt, 0);
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

/* Computes checksum for a fixed 20-byte header (no IP/TCP options).
 * Only valid because the dataplane currently accepts only ihl=5 IPv4 packets.
 */
static __always_inline __u16 ipv4_header_csum(struct iphdr *iph)
{
    __u32 csum = 0;
    __u16 *w = (__u16 *)iph;

    csum += w[0]; csum += w[1]; csum += w[2]; csum += w[3];
    csum += w[4]; csum += w[5]; csum += w[6]; csum += w[7];
    csum += w[8]; csum += w[9];

    return csum_fold_helper(csum);
}

/* Computes checksum for a fixed 20-byte header (no IP/TCP options).
 * Only valid because do_tcp_reset_tx sets ihl=5 and doff=5.
 */
static __always_inline __u16 tcp_rst_csum(__be32 saddr, __be32 daddr,
                                           struct tcphdr *tcp)
{
    __u32 csum = 0;
    __u16 *w;

    w = (__u16 *)&saddr; csum += w[0]; csum += w[1];
    w = (__u16 *)&daddr; csum += w[0]; csum += w[1];
    csum += bpf_htons((__u16)IPPROTO_TCP);
    csum += bpf_htons((__u16)sizeof(*tcp));

    w = (__u16 *)tcp;
    csum += w[0]; csum += w[1]; csum += w[2]; csum += w[3];
    csum += w[4]; csum += w[5]; csum += w[6]; csum += w[7];
    csum += w[8]; csum += w[9];

    return csum_fold_helper(csum);
}

/* Computes checksum for fixed ICMP unreachable content:
 *   8-byte icmp header + 20-byte quoted IPv4 header + 8-byte L4 quote.
 */
static __always_inline __u16 icmp_unreach_csum(struct icmphdr *icmp)
{
    __u32 csum = 0;
    __u16 *w = (__u16 *)icmp;
    int i;

    #pragma clang loop unroll(full)
    for (i = 0; i < 18; i++)
        csum += w[i];

    return csum_fold_helper(csum);
}

static __always_inline void set_tcp_rst_flags(struct tcphdr *tcp, __u8 ack)
{
    tcp->fin = 0;
    tcp->syn = 0;
    tcp->rst = 1;
    tcp->psh = 0;
    tcp->ack = ack;
    tcp->urg = 0;
    tcp->ece = 0;
    tcp->cwr = 0;
}

static __always_inline int tx_failure_verdict(const struct tx_config *cfg)
{
    if (cfg && cfg->tcp_reset_failure_verdict == TCP_RESET_FAILURE_DROP)
        return XDP_DROP;
    return XDP_PASS;
}

static __always_inline int ingress_failure_verdict(const struct global_cfg *cfg)
{
    if (cfg && cfg->ingress_verdict == INGRESS_FAILURE_DROP)
        return XDP_DROP;
    return XDP_PASS;
}

static __always_inline int tx_mutated_failure(void)
{
    return XDP_DROP;
}

static __always_inline int strip_vlan_header(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth = data;
    struct vlan_hdr *vlan;

    if ((void *)(eth + 1) > data_end)
        return -1;
    vlan = (void *)(eth + 1);
    if ((void *)(vlan + 1) > data_end)
        return -1;
    if (bpf_ntohs(eth->h_proto) != ETH_P_8021Q)
        return -1;

    __builtin_memmove(data + VLAN_HLEN, data, 2 * ETH_ALEN);
    if (bpf_xdp_adjust_head(xdp, VLAN_HLEN))
        return -1;

    return 0;
}

static __always_inline int lookup_tx_fib(struct xdp_md *xdp,
                                         const struct tx_config *cfg,
                                         __u8 tos,
                                         __u8 l4_protocol,
                                         __u16 tot_len,
                                         __be32 saddr,
                                         __be32 daddr,
                                         struct bpf_fib_lookup *fib)
{
    int fib_ret;

    if (!cfg || cfg->tcp_reset_egress_ifindex == 0) {
        stat_inc(STAT_REDIRECT_FAILED);
        return -1;
    }

    fib->family = AF_INET;
    fib->ifindex = cfg->tcp_reset_egress_ifindex;
    fib->l4_protocol = l4_protocol;
    fib->tot_len = tot_len;
    fib->ipv4_src = saddr;
    fib->ipv4_dst = daddr;
    fib->tos = tos;

    fib_ret = bpf_fib_lookup(xdp, fib, sizeof(*fib), BPF_FIB_LOOKUP_OUTPUT);
    if (fib_ret != BPF_FIB_LKUP_RET_SUCCESS) {
        stat_inc(STAT_FIB_LOOKUP_FAILED);
        return -1;
    }

    return 0;
}

static __always_inline int redirect_kernel_tx(struct xdp_md *xdp,
                                              const struct pkt_ctx *ctx,
                                              const struct tx_config *cfg,
                                              const struct bpf_fib_lookup *fib)
{
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct vlan_hdr *vlan;
    struct iphdr *ip;
    int l3_off;

    if (ctx->vlan_id != VLAN_ID_NONE &&
        cfg->tcp_reset_vlan_mode == TCP_RESET_VLAN_ACCESS) {
        if (strip_vlan_header(xdp)) {
            stat_inc(STAT_REDIRECT_FAILED);
            return tx_mutated_failure();
        }
    }

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;
    eth = data;
    if ((void *)(eth + 1) > data_end) {
        stat_inc(STAT_REDIRECT_FAILED);
        return tx_mutated_failure();
    }

    if (bpf_ntohs(eth->h_proto) == ETH_P_8021Q) {
        vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end) {
            stat_inc(STAT_REDIRECT_FAILED);
            return tx_mutated_failure();
        }
        l3_off = sizeof(*eth) + sizeof(*vlan);
    } else {
        l3_off = sizeof(*eth);
    }

    ip = data + l3_off;
    if ((void *)(ip + 1) > data_end) {
        stat_inc(STAT_REDIRECT_FAILED);
        return tx_mutated_failure();
    }

    __builtin_memcpy(eth->h_source, fib->smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, fib->dmac, ETH_ALEN);

    return bpf_redirect(fib->ifindex, 0);
}

static __always_inline int do_tcp_reset_tx(struct xdp_md *xdp,
                                           const struct pkt_ctx *ctx)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth;
    struct vlan_hdr *vlan;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u8 tmp_mac[ETH_ALEN];
    __be32 tmp_addr;
    __u16 tmp_port;
    int target_len;
    int l3_off;
    __u32 zero = 0;
    struct tx_config *tx_cfg;
    struct bpf_fib_lookup fib = {};
    int redirect = 0;

    if (ctx->ip_proto != IPPROTO_TCP)
        return XDP_PASS;
    tx_cfg = bpf_map_lookup_elem(&tx_config_map, &zero);
    if (tx_cfg && tx_cfg->tcp_reset_mode == TCP_RESET_TX_MODE_REDIRECT)
        redirect = 1;

    if (ctx->vlan_id != VLAN_ID_NONE) {
        target_len = sizeof(*eth) + sizeof(*vlan) + sizeof(*ip) + sizeof(*tcp);
        l3_off = sizeof(*eth) + sizeof(*vlan);
    } else {
        target_len = sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
        l3_off = sizeof(*eth);
    }

    if (redirect) {
        ip = data + l3_off;
        if ((void *)(ip + 1) > data_end) {
            stat_inc(STAT_REDIRECT_FAILED);
            return tx_failure_verdict(tx_cfg);
        }
        if (lookup_tx_fib(xdp, tx_cfg, ip->tos, IPPROTO_TCP,
                          sizeof(struct iphdr) + sizeof(struct tcphdr),
                          ctx->daddr, ctx->saddr, &fib))
            return tx_failure_verdict(tx_cfg);
    }

    if (bpf_xdp_adjust_tail(xdp, target_len - (data_end - data)))
        return tx_failure_verdict(tx_cfg);

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return tx_failure_verdict(tx_cfg);

    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    if (ctx->vlan_id != VLAN_ID_NONE) {
        vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return tx_failure_verdict(tx_cfg);
    }

    ip = data + l3_off;
    if ((void *)(ip + 1) > data_end)
        return tx_failure_verdict(tx_cfg);
    tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return tx_failure_verdict(tx_cfg);

    tmp_addr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_addr;

    ip->tot_len = bpf_htons(sizeof(*ip) + sizeof(*tcp));
    ip->check = 0;
    ip->check = ipv4_header_csum(ip);

    tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    tcp->doff = 5;
    tcp->window = 0;
    tcp->urg_ptr = 0;
    tcp->res1 = 0;
    tcp->check = 0;

    if (ctx->tcp_flags & TCP_FLAG_ACK) {
        tcp->seq = tcp->ack_seq;
        tcp->ack_seq = 0;
        set_tcp_rst_flags(tcp, 0);
    } else {
        __u32 ack_val = bpf_ntohl(tcp->seq);
        ack_val += ctx->payload_len;
        if (ctx->tcp_flags & TCP_FLAG_SYN)
            ack_val++;
        if (ctx->tcp_flags & TCP_FLAG_FIN)
            ack_val++;
        tcp->ack_seq = bpf_htonl(ack_val);
        tcp->seq = 0;
        set_tcp_rst_flags(tcp, 1);
    }

    tcp->check = tcp_rst_csum(ip->saddr, ip->daddr, tcp);

    if (redirect)
        return redirect_kernel_tx(xdp, ctx, tx_cfg, &fib);

    return XDP_TX;
}

static __always_inline int do_icmp_dest_unreachable_tx(struct xdp_md *xdp,
                                                       const struct pkt_ctx *ctx,
                                                       __u8 icmp_code)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct ethhdr *eth;
    struct vlan_hdr *vlan;
    struct iphdr *ip;
    struct udphdr *udp;
    struct icmphdr *icmp;
    __u8 *quote;
    __u8 tmp_mac[ETH_ALEN];
    __u8 quoted[sizeof(struct iphdr) + 8];
    __be32 tmp_addr;
    int target_len;
    int l3_off;
    __u32 zero = 0;
    struct tx_config *tx_cfg;
    struct bpf_fib_lookup fib = {};
    int redirect = 0;

    if (ctx->ip_proto != IPPROTO_UDP)
        return XDP_PASS;

    tx_cfg = bpf_map_lookup_elem(&tx_config_map, &zero);
    if (tx_cfg && tx_cfg->tcp_reset_mode == TCP_RESET_TX_MODE_REDIRECT)
        redirect = 1;

    if (ctx->vlan_id != VLAN_ID_NONE) {
        target_len = sizeof(*eth) + sizeof(*vlan) + sizeof(*ip) +
                     sizeof(*icmp) + sizeof(quoted);
        l3_off = sizeof(*eth) + sizeof(*vlan);
    } else {
        target_len = sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + sizeof(quoted);
        l3_off = sizeof(*eth);
    }

    ip = data + l3_off;
    if ((void *)(ip + 1) > data_end)
        return tx_failure_verdict(tx_cfg);
    udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return tx_failure_verdict(tx_cfg);

    __builtin_memcpy(quoted, ip, sizeof(struct iphdr));
    __builtin_memcpy(quoted + sizeof(struct iphdr), udp, 8);

    if (redirect) {
        if (lookup_tx_fib(xdp, tx_cfg, ip->tos, IPPROTO_ICMP,
                          sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(quoted),
                          ctx->daddr, ctx->saddr, &fib))
            return tx_failure_verdict(tx_cfg);
    }

    if (bpf_xdp_adjust_tail(xdp, target_len - (data_end - data)))
        return tx_failure_verdict(tx_cfg);

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return tx_failure_verdict(tx_cfg);

    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    if (ctx->vlan_id != VLAN_ID_NONE) {
        vlan = (void *)(eth + 1);
        if ((void *)(vlan + 1) > data_end)
            return tx_failure_verdict(tx_cfg);
    }

    ip = data + l3_off;
    if ((void *)(ip + 1) > data_end)
        return tx_failure_verdict(tx_cfg);
    icmp = (void *)(ip + 1);
    quote = (void *)(icmp + 1);
    if ((void *)(quote + sizeof(quoted)) > data_end)
        return tx_failure_verdict(tx_cfg);

    tmp_addr = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_addr;
    ip->protocol = IPPROTO_ICMP;
    ip->ttl = 64;
    ip->frag_off = 0;
    ip->tot_len = bpf_htons(sizeof(*ip) + sizeof(*icmp) + sizeof(quoted));
    ip->check = 0;
    ip->check = ipv4_header_csum(ip);

    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = icmp_code;
    icmp->checksum = 0;
    icmp->un.gateway = 0;
    __builtin_memcpy(quote, quoted, sizeof(quoted));
    icmp->checksum = icmp_unreach_csum(icmp);

    if (redirect)
        return redirect_kernel_tx(xdp, ctx, tx_cfg, &fib);

    return XDP_TX;
}

static __always_inline int redirect_xsk_with_meta(struct xdp_md *xdp,
                                                  const struct rule_meta *rule,
                                                  const struct global_cfg *cfg)
{
    void *data;
    void *data_meta;
    struct xsk_meta *meta;
    int redir;
    int fallback = ingress_failure_verdict(cfg);

    if (bpf_xdp_adjust_meta(xdp, -(int)sizeof(*meta))) {
        stat_inc(STAT_XSK_META_FAILED);
        stat_inc(STAT_XSK_FAILED);
        return fallback;
    }

    data = (void *)(long)xdp->data;
    data_meta = (void *)(long)xdp->data_meta;
    meta = data_meta;
    if ((void *)(meta + 1) > data) {
        stat_inc(STAT_XSK_META_FAILED);
        stat_inc(STAT_XSK_FAILED);
        return fallback;
    }

    meta->rule_id = rule->rule_id;
    meta->action = rule->action;
    meta->reserved = 0;

    redir = bpf_redirect_map(&xsks_map, xdp->rx_queue_index, fallback);
    if (redir == XDP_REDIRECT)
        return XDP_REDIRECT;

    stat_inc(STAT_XSK_REDIRECT_FAILED);
    stat_inc(STAT_XSK_FAILED);
    return fallback;
}

static __always_inline int can_tcp_syn_ack(const struct pkt_ctx *ctx)
{
    return (ctx->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST | TCP_FLAG_FIN)) == TCP_FLAG_SYN;
}

static parse_err_t parse_udp(struct pkt_ctx *ctx, void *data, void *data_end, __u32 l4_len)
{
    struct udphdr *udp = data;
    __u32 udp_len;

    if ((void *)(udp + 1) > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp) || udp_len > l4_len)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->sport = bpf_ntohs(udp->source);
    ctx->dport = bpf_ntohs(udp->dest);
    if (ctx->sport != 0)
        ctx->conds |= COND_SRC_PORT;
    if (ctx->dport != 0)
        ctx->conds |= COND_DST_PORT;

    ctx->payload_len = (__u16)(udp_len - sizeof(*udp));
    if (ctx->payload_len > 0)
        ctx->conds |= COND_L4_PAYLOAD;
    return PARSE_OK;
}

/* ICMP parser support. */
static __always_inline parse_err_t parse_icmp(struct pkt_ctx *ctx, void *data, void *data_end, __u32 l4_len)
{
    struct icmphdr *icmp = data;
    __u8 icmp_type;
    __u8 icmp_code;

    if ((void *)(icmp + 1) > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;
    if (sizeof(*icmp) > l4_len)
        return PARSE_ERR_TRANSPORT_SHORT;

    icmp_type = icmp->type;
    icmp_code = icmp->code;
    if (icmp_code == 0) {
        if (icmp_type == 8)
            ctx->conds |= COND_ICMP_ECHO_REQUEST;
        if (icmp_type == 0)
            ctx->conds |= COND_ICMP_ECHO_REPLY;
    }

    ctx->payload_len = (__u16)(l4_len - sizeof(*icmp));
    if (ctx->payload_len > 0)
        ctx->conds |= COND_L4_PAYLOAD;
    return PARSE_OK;
}

static parse_err_t parse_tcp(struct pkt_ctx *ctx, void *data, void *data_end, __u32 l4_len)
{
    struct tcphdr *tcp = data;
    __u32 doff_len;

    if ((void *)(tcp + 1) > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    doff_len = tcp->doff * 4;
    if (doff_len < sizeof(*tcp) || doff_len > l4_len)
        return PARSE_ERR_TRANSPORT_SHORT;
    if ((void *)tcp + doff_len > data_end)
        return PARSE_ERR_TRANSPORT_SHORT;

    ctx->sport = bpf_ntohs(tcp->source);
    ctx->dport = bpf_ntohs(tcp->dest);
    if (ctx->sport != 0)
        ctx->conds |= COND_SRC_PORT;
    if (ctx->dport != 0)
        ctx->conds |= COND_DST_PORT;

    ctx->tcp_flags = ((__u8 *)tcp)[13] &
        (TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_PSH | TCP_FLAG_ACK);
    ctx->conds |= TCP_FLAG_TO_COND(ctx->tcp_flags, TCP_FLAG_SYN, COND_TCP_SYN) |
                  TCP_FLAG_TO_COND(ctx->tcp_flags, TCP_FLAG_ACK, COND_TCP_ACK) |
                  TCP_FLAG_TO_COND(ctx->tcp_flags, TCP_FLAG_RST, COND_TCP_RST) |
                  TCP_FLAG_TO_COND(ctx->tcp_flags, TCP_FLAG_FIN, COND_TCP_FIN) |
                  TCP_FLAG_TO_COND(ctx->tcp_flags, TCP_FLAG_PSH, COND_TCP_PSH);

    ctx->payload_len = (__u16)(l4_len - doff_len);
    if (ctx->payload_len > 0)
        ctx->conds |= COND_L4_PAYLOAD;
    return PARSE_OK;
}

static parse_err_t parse_ip_l4(struct pkt_ctx *ctx, void *l4,
                               void *data_end, __u8 ip_proto, __u32 l4_len)
{
    ctx->ip_proto = ip_proto;

    switch (ip_proto) {
    case IPPROTO_TCP:
        ctx->conds |= COND_PROTO_TCP;
        return parse_tcp(ctx, l4, data_end, l4_len);
    case IPPROTO_UDP:
        ctx->conds |= COND_PROTO_UDP;
        return parse_udp(ctx, l4, data_end, l4_len);
    case IPPROTO_ICMP:
        ctx->conds |= COND_PROTO_ICMP;
        return parse_icmp(ctx, l4, data_end, l4_len);
    default:
        return PARSE_ERR_UNSUPPORTED_IP_PROTO;
    }
}

static parse_err_t parse_ipv4(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct iphdr *ip = data;
    __u32 total_len;
    __u32 captured_len;
    void *l4;

    if ((void *)(ip + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;

    total_len = bpf_ntohs(ip->tot_len);
    captured_len = (__u32)((long)data_end - (long)data);
    if (ip->ihl != 5 || total_len < sizeof(*ip) || total_len > captured_len)
        return PARSE_ERR_BAD_IPV4;

    ctx->saddr = ip->saddr;
    ctx->daddr = ip->daddr;

    l4 = ip + 1;
    return parse_ip_l4(ctx, l4, data_end, ip->protocol, total_len - sizeof(*ip));
}

/* ARP parser support. */
static __always_inline parse_err_t parse_arp(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct arphdr *arp = data;
    struct arp_eth_ipv4 *arp4;
    __u16 arp_op;

    if ((void *)(arp + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;
    if (arp->ar_hrd != bpf_htons(ARPHRD_ETHER))
        return PARSE_ERR_BAD_ARP;
    if (arp->ar_pro != bpf_htons(ETH_P_IP))
        return PARSE_ERR_BAD_ARP;
    if (arp->ar_hln != ETH_ALEN || arp->ar_pln != 4)
        return PARSE_ERR_BAD_ARP;

    arp_op = bpf_ntohs(arp->ar_op);
    ctx->conds |= COND_PROTO_ARP;
    if (arp_op == 1)
        ctx->conds |= COND_ARP_REQUEST;
    if (arp_op == 2)
        ctx->conds |= COND_ARP_REPLY;

    arp4 = (void *)(arp + 1);
    if ((void *)(arp4 + 1) > data_end)
        return PARSE_ERR_NETWORK_SHORT;

    ctx->ip_proto = 0;
    __builtin_memcpy(&ctx->saddr, arp4->sip, sizeof(ctx->saddr));
    __builtin_memcpy(&ctx->daddr, arp4->dip, sizeof(ctx->daddr));
    return PARSE_OK;
}

static parse_err_t parse_vlan(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct vlan_hdr *vh = data;
    __u16 encap;

    if ((void *)(vh + 1) > data_end)
        return PARSE_ERR_ETH_SHORT;

    ctx->vlan_id = bpf_ntohs(vh->tci) & 0x0fff;
    encap = bpf_ntohs(vh->encapsulated_proto);
    ctx->conds |= COND_VLAN;

    if (encap == ETH_P_8021Q)
        return PARSE_ERR_BAD_VLAN;

    switch (encap) {
    case ETH_P_IP:
        return parse_ipv4(ctx, vh + 1, data_end);
    case ETH_P_ARP:
        return parse_arp(ctx, vh + 1, data_end);
    default:
        return PARSE_ERR_UNSUPPORTED_ETH_PROTO;
    }
}

static parse_err_t parse_packet(struct pkt_ctx *ctx, void *data, void *data_end)
{
    struct ethhdr *eth = data;
    __u16 proto;

    ctx->vlan_id = VLAN_ID_NONE;
    ctx->ip_proto = 0;
    ctx->sport = 0;
    ctx->dport = 0;
    ctx->tcp_flags = 0;
    ctx->payload_len = 0;
    ctx->conds = 0;

    if ((void *)(eth + 1) > data_end)
        return PARSE_ERR_ETH_SHORT;

    proto = bpf_ntohs(eth->h_proto);

    switch (proto) {
    case ETH_P_8021Q:
        return parse_vlan(ctx, eth + 1, data_end);
    case ETH_P_IP:
        return parse_ipv4(ctx, eth + 1, data_end);
    case ETH_P_ARP:
        return parse_arp(ctx, eth + 1, data_end);
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
    __u32 pkt_conds;
    __u32 zero = 0;
    parse_err_t err;

    stat_inc(STAT_RX_PACKETS);

    cfg = bpf_map_lookup_elem(&global_cfg_map, &zero);

    err = parse_packet(&ctx, data, data_end);
    if (err != PARSE_OK) {
        stat_inc(STAT_PARSE_FAILED);
        return ingress_failure_verdict(cfg);
    }
    pkt_conds = ctx.conds;

    if (!cfg)
        return ingress_failure_verdict(cfg);

    mask_copy(&candidates, &cfg->all_active_rules);

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
        return ingress_failure_verdict(cfg);

    stat_inc(STAT_RULE_CANDIDATES);

    if (!pick_best_rule(&candidates, pkt_conds, &best_rule))
        return ingress_failure_verdict(cfg);

    stat_inc(STAT_MATCHED_RULES);

    switch (best_rule.action) {
    case ACTION_TCP_RESET:
    case ACTION_ICMP_PORT_UNREACHABLE:
    case ACTION_ICMP_HOST_UNREACHABLE:
    case ACTION_ICMP_ADMIN_PROHIBITED: {
        int ret;
        if (best_rule.action == ACTION_TCP_RESET && (ctx.tcp_flags & TCP_FLAG_RST))
            return XDP_PASS;
        if (best_rule.action == ACTION_TCP_RESET)
            ret = do_tcp_reset_tx(xdp, &ctx);
        else
            ret = do_icmp_dest_unreachable_tx(
                xdp,
                &ctx,
                best_rule.action == ACTION_ICMP_PORT_UNREACHABLE
                    ? ICMP_PORT_UNREACH
                    : best_rule.action == ACTION_ICMP_HOST_UNREACHABLE
                        ? ICMP_HOST_UNREACH
                        : ICMP_PKT_FILTERED);
        if (ret == XDP_TX) {
            stat_inc(STAT_XDP_TX);
            emit_event(&ctx, &best_rule, pkt_conds, VERDICT_TX);
            return XDP_TX;
        }
        if (ret == XDP_REDIRECT) {
            stat_inc(STAT_REDIRECT_TX);
            emit_event(&ctx, &best_rule, pkt_conds, VERDICT_REDIRECT_TX);
            return XDP_REDIRECT;
        }
        if (ret == XDP_DROP) {
            stat_inc(STAT_TX_FAILED);
            return XDP_DROP;
        }
        stat_inc(STAT_TX_FAILED);
        return XDP_PASS;
    }
    case ACTION_ICMP_ECHO_REPLY:
    case ACTION_ARP_REPLY:
    case ACTION_TCP_SYN_ACK:
    case ACTION_UDP_ECHO_REPLY:
    case ACTION_DNS_REFUSED: {
        int redir;
        if (best_rule.action == ACTION_TCP_SYN_ACK && !can_tcp_syn_ack(&ctx))
            return ingress_failure_verdict(cfg);
        redir = redirect_xsk_with_meta(xdp, &best_rule, cfg);
        if (redir == XDP_REDIRECT) {
            stat_inc(STAT_XSK_TX);
            emit_event(&ctx, &best_rule, pkt_conds, VERDICT_XSK);
            return XDP_REDIRECT;
        }
        return redir;
    }
    case ACTION_ALERT:
        emit_event(&ctx, &best_rule, pkt_conds, VERDICT_OBSERVE);
        return ingress_failure_verdict(cfg);
    case ACTION_NONE:
    default:
        return ingress_failure_verdict(cfg);
    }
}

char LICENSE[] SEC("license") = "GPL";
