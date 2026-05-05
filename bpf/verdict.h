#ifndef SIDERSP_BPF_VERDICT_H
#define SIDERSP_BPF_VERDICT_H

#include <bpf/bpf_endian.h>

#include "match.h"
#include "netdefs.h"

static __always_inline void stat_inc(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);

    if (val)
        (*val)++;
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

static __always_inline int do_tcp_reset_tx(struct xdp_md *xdp,
                                           const struct pkt_ctx *ctx);

static __always_inline int do_icmp_dest_unreachable_tx(struct xdp_md *xdp,
                                                       const struct pkt_ctx *ctx,
                                                       __u8 icmp_code);

static __always_inline int run_kernel_tx_action(struct xdp_md *xdp,
                                                const struct pkt_ctx *ctx,
                                                const struct rule_meta *rule,
                                                __u32 pkt_conds)
{
    __u8 icmp_code;
    int ret;

    if (rule->action == ACTION_TCP_RESET) {
        if (ctx->tcp_flags & TCP_FLAG_RST)
            return XDP_PASS;
        ret = do_tcp_reset_tx(xdp, ctx);
    } else {
        icmp_code = ICMP_PKT_FILTERED;
        if (rule->action == ACTION_ICMP_PORT_UNREACHABLE)
            icmp_code = ICMP_PORT_UNREACH;
        else if (rule->action == ACTION_ICMP_HOST_UNREACHABLE)
            icmp_code = ICMP_HOST_UNREACH;
        ret = do_icmp_dest_unreachable_tx(xdp, ctx, icmp_code);
    }

    if (ret == XDP_TX || ret == XDP_REDIRECT) {
        store_flow_cache(ctx, rule);
        stat_inc(ret == XDP_TX ? STAT_XDP_TX : STAT_REDIRECT_TX);
        emit_event(ctx, rule, pkt_conds,
                   ret == XDP_TX ? VERDICT_TX : VERDICT_REDIRECT_TX);
        return ret;
    }

    stat_inc(STAT_TX_FAILED);
    if (ret == XDP_DROP)
        return XDP_DROP;
    return XDP_PASS;
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

struct kernel_tx_ctx {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    int target_len;
    struct tx_config *tx_cfg;
    struct bpf_fib_lookup fib;
    int redirect;
};

static __always_inline void init_kernel_tx_ctx(struct xdp_md *xdp,
                                               const struct pkt_ctx *ctx,
                                               int l4_len,
                                               int l4_extra_len,
                                               struct kernel_tx_ctx *tx)
{
    __u32 zero = 0;

    tx->data = (void *)(long)xdp->data;
    tx->data_end = (void *)(long)xdp->data_end;
    tx->eth = 0;
    tx->ip = 0;
    tx->target_len = sizeof(struct ethhdr) + sizeof(struct iphdr) + l4_len + l4_extra_len;
    if (ctx->vlan_id != VLAN_ID_NONE)
        tx->target_len += sizeof(struct vlan_hdr);
    tx->tx_cfg = bpf_map_lookup_elem(&tx_config_map, &zero);
    tx->redirect = tx->tx_cfg &&
                   tx->tx_cfg->tcp_reset_mode == TCP_RESET_TX_MODE_REDIRECT;
}

static __always_inline int expand_kernel_tx_frame(struct xdp_md *xdp,
                                                  const struct pkt_ctx *ctx,
                                                  struct kernel_tx_ctx *tx)
{
    struct vlan_hdr *vlan;
    __u8 tmp_mac[ETH_ALEN];

    if (bpf_xdp_adjust_tail(xdp, tx->target_len - (tx->data_end - tx->data)))
        return tx_failure_verdict(tx->tx_cfg);

    tx->data = (void *)(long)xdp->data;
    tx->data_end = (void *)(long)xdp->data_end;

    tx->eth = tx->data;
    if ((void *)(tx->eth + 1) > tx->data_end)
        return tx_failure_verdict(tx->tx_cfg);

    __builtin_memcpy(tmp_mac, tx->eth->h_source, ETH_ALEN);
    __builtin_memcpy(tx->eth->h_source, tx->eth->h_dest, ETH_ALEN);
    __builtin_memcpy(tx->eth->h_dest, tmp_mac, ETH_ALEN);

    if (ctx->vlan_id != VLAN_ID_NONE) {
        vlan = (void *)(tx->eth + 1);
        if ((void *)(vlan + 1) > tx->data_end)
            return tx_failure_verdict(tx->tx_cfg);
        tx->ip = (void *)(vlan + 1);
    } else {
        tx->ip = (void *)(tx->eth + 1);
    }

    if ((void *)(tx->ip + 1) > tx->data_end)
        return tx_failure_verdict(tx->tx_cfg);

    return 0;
}

static __always_inline int finish_kernel_tx(struct xdp_md *xdp,
                                            const struct pkt_ctx *ctx,
                                            const struct kernel_tx_ctx *tx)
{
    if (tx->redirect)
        return redirect_kernel_tx(xdp, ctx, tx->tx_cfg, &tx->fib);

    return XDP_TX;
}

static __always_inline int do_tcp_reset_tx(struct xdp_md *xdp,
                                           const struct pkt_ctx *ctx)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    __be32 tmp_addr;
    __u16 tmp_port;
    struct kernel_tx_ctx tx = {};
    int ret;

    if (ctx->ip_proto != IPPROTO_TCP)
        return XDP_PASS;

    init_kernel_tx_ctx(xdp, ctx, sizeof(*tcp), 0, &tx);

    if (tx.redirect) {
        if (ctx->vlan_id != VLAN_ID_NONE)
            ip = tx.data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
        else
            ip = tx.data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > tx.data_end) {
            stat_inc(STAT_REDIRECT_FAILED);
            return tx_failure_verdict(tx.tx_cfg);
        }
        if (lookup_tx_fib(xdp, tx.tx_cfg, ip->tos, IPPROTO_TCP,
                          sizeof(struct iphdr) + sizeof(struct tcphdr),
                          ctx->daddr, ctx->saddr, &tx.fib))
            return tx_failure_verdict(tx.tx_cfg);
    }

    ret = expand_kernel_tx_frame(xdp, ctx, &tx);
    if (ret)
        return ret;

    ip = tx.ip;
    tcp = (void *)(tx.ip + 1);
    if ((void *)(tcp + 1) > tx.data_end)
        return tx_failure_verdict(tx.tx_cfg);

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

    return finish_kernel_tx(xdp, ctx, &tx);
}

static __always_inline int do_icmp_dest_unreachable_tx(struct xdp_md *xdp,
                                                       const struct pkt_ctx *ctx,
                                                       __u8 icmp_code)
{
    struct iphdr *ip;
    struct udphdr *udp;
    struct icmphdr *icmp;
    __u8 *quote;
    __u8 quoted[sizeof(struct iphdr) + 8];
    __be32 tmp_addr;
    struct kernel_tx_ctx tx = {};
    int ret;

    if (ctx->ip_proto != IPPROTO_UDP)
        return XDP_PASS;

    init_kernel_tx_ctx(xdp, ctx, sizeof(*icmp), sizeof(quoted), &tx);

    if (ctx->vlan_id != VLAN_ID_NONE)
        ip = tx.data + sizeof(struct ethhdr) + sizeof(struct vlan_hdr);
    else
        ip = tx.data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > tx.data_end)
        return tx_failure_verdict(tx.tx_cfg);
    udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > tx.data_end)
        return tx_failure_verdict(tx.tx_cfg);

    __builtin_memcpy(quoted, ip, sizeof(struct iphdr));
    __builtin_memcpy(quoted + sizeof(struct iphdr), udp, 8);

    if (tx.redirect) {
        if (lookup_tx_fib(xdp, tx.tx_cfg, ip->tos, IPPROTO_ICMP,
                          sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(quoted),
                          ctx->daddr, ctx->saddr, &tx.fib))
            return tx_failure_verdict(tx.tx_cfg);
    }

    ret = expand_kernel_tx_frame(xdp, ctx, &tx);
    if (ret)
        return ret;

    ip = tx.ip;
    icmp = (void *)(tx.ip + 1);
    quote = (void *)(icmp + 1);
    if ((void *)(quote + sizeof(quoted)) > tx.data_end)
        return tx_failure_verdict(tx.tx_cfg);

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

    return finish_kernel_tx(xdp, ctx, &tx);
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

#endif
