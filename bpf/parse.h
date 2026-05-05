#ifndef SIDERSP_BPF_PARSE_H
#define SIDERSP_BPF_PARSE_H

#include <bpf/bpf_endian.h>

#include "netdefs.h"
#include "rule.h"

#define TCP_FLAG_TO_COND(flags, flag, cond) \
    (((__u32)((flags) & (flag))) << (__builtin_ctz(cond) - __builtin_ctz(flag)))

struct arp_eth_ipv4 {
    __u8 sha[ETH_ALEN];
    __u8 sip[4];
    __u8 tha[ETH_ALEN];
    __u8 dip[4];
};

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

    ctx->vlan_id = bpf_ntohs(vh->h_vlan_TCI) & 0x0fff;
    encap = bpf_ntohs(vh->h_vlan_encapsulated_proto);
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

#endif
