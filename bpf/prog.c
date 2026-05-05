#include "headers/vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "verdict.h"
#include "parse.h"

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

    if (lookup_flow_cache(&ctx, &best_rule)) {
        stat_inc(STAT_RULE_CANDIDATES);
        stat_inc(STAT_MATCHED_RULES);
    } else {
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
    }

    switch (best_rule.action) {
    case ACTION_TCP_RESET:
    case ACTION_ICMP_PORT_UNREACHABLE:
    case ACTION_ICMP_HOST_UNREACHABLE:
    case ACTION_ICMP_ADMIN_PROHIBITED:
        return run_kernel_tx_action(xdp, &ctx, &best_rule, pkt_conds);
    case ACTION_ICMP_ECHO_REPLY:
    case ACTION_ARP_REPLY:
    case ACTION_TCP_SYN_ACK:
    case ACTION_UDP_ECHO_REPLY:
    case ACTION_DNS_REFUSED:
    case ACTION_DNS_SINKHOLE: {
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
