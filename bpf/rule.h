/*
 * Shared data structures for the XDP data plane.
 *
 * Overall pipeline:
 *
 *   parse_packet() → index pre-filter
 *       → pick best rule → execute action → emit event
 *
 * See docs/bpf-dataplane-spec.md for the full flow diagram.
 */
#ifndef SIDERSP_BPF_RULE_H
#define SIDERSP_BPF_RULE_H

#include <linux/types.h>

#include "mask.h"

#define VLAN_ID_NONE 0xffff

/*
 * Packet condition bits — set while parsing in prog.c.
 * Each bit indicates that the packet exhibits a particular property.
 * rule_meta.required_mask uses these bits to express which conditions
 * a rule requires for a match.
 *
 *   Bits 0–3:   L3/L2 protocol
 *   Bits 4–8:   indexable conditions
 *   Bits 9–13:  TCP flags
 *   Bits 14–15: ICMP type
 *   Bits 16–17: ARP operation
 *   Bit 18:     L4 payload
 */
#define COND_PROTO_TCP         (1U << 0)
#define COND_PROTO_UDP         (1U << 1)
#define COND_PROTO_ICMP        (1U << 2)
#define COND_PROTO_ARP         (1U << 3)
#define COND_VLAN              (1U << 4)
#define COND_SRC_PREFIX        (1U << 5)
#define COND_DST_PREFIX        (1U << 6)
#define COND_SRC_PORT          (1U << 7)
#define COND_DST_PORT          (1U << 8)
#define COND_TCP_SYN           (1U << 9)
#define COND_TCP_ACK           (1U << 10)
#define COND_TCP_RST           (1U << 11)
#define COND_TCP_FIN           (1U << 12)
#define COND_TCP_PSH           (1U << 13)
#define COND_ICMP_ECHO_REQUEST (1U << 14)
#define COND_ICMP_ECHO_REPLY   (1U << 15)
#define COND_ARP_REQUEST       (1U << 16)
#define COND_ARP_REPLY         (1U << 17)
#define COND_L4_PAYLOAD        (1U << 18)

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10

typedef enum {
    PARSE_OK = 0,
    PARSE_ERR_ETH_SHORT,
    PARSE_ERR_NETWORK_SHORT,
    PARSE_ERR_TRANSPORT_SHORT,
    PARSE_ERR_UNSUPPORTED_ETH_PROTO,
    PARSE_ERR_UNSUPPORTED_IP_PROTO,
    PARSE_ERR_BAD_VLAN,
    PARSE_ERR_BAD_ARP,
    PARSE_ERR_BAD_IPV4,
} parse_err_t;

enum rule_action {
    ACTION_NONE            = 0,
    ACTION_ALERT           = 1,
    ACTION_TCP_RESET       = 2,
    ACTION_ICMP_ECHO_REPLY = 3,
    ACTION_ARP_REPLY       = 4,
    ACTION_TCP_SYN_ACK     = 5,
    ACTION_ICMP_PORT_UNREACHABLE = 6,
    ACTION_UDP_ECHO_REPLY        = 7,
    ACTION_DNS_REFUSED           = 8,
};

enum dataplane_verdict {
    VERDICT_OBSERVE = 0,
    VERDICT_TX      = 1,
    VERDICT_XSK     = 2,
    VERDICT_REDIRECT_TX = 3,
};

enum tcp_reset_tx_mode {
    TCP_RESET_TX_MODE_XDP_TX   = 0,
    TCP_RESET_TX_MODE_REDIRECT = 1,
};

enum tcp_reset_vlan_mode {
    TCP_RESET_VLAN_PRESERVE = 0,
    TCP_RESET_VLAN_ACCESS   = 1,
};

enum tcp_reset_failure_verdict {
    TCP_RESET_FAILURE_PASS = 0,
    TCP_RESET_FAILURE_DROP = 1,
};

enum ingress_failure_verdict {
    INGRESS_FAILURE_PASS = 0,
    INGRESS_FAILURE_DROP = 1,
};

/* Per-packet parsing result (stack-only, never shared with userspace). */
struct pkt_ctx {
    __u16 vlan_id;

    __u8 ip_proto;

    __be32 saddr;
    __be32 daddr;

    __u16 sport;
    __u16 dport;

    __u8 tcp_flags;
    __u16 payload_len;
    __u32 conds;
};

/*
 * Per-slot rule metadata (stored in rule_index_map, written by control plane).
 * Dataplane sync guarantees slot order reflects priority.
 *
 * Final match check:
 *   (pkt_conds & rule->required_mask) == rule->required_mask
 */
struct rule_meta {
    __u32 rule_id;
    __u32 required_mask;
    __u16 action;
    __u8  flags;
};

struct global_cfg {
    mask_t all_active_rules;
    mask_t vlan_optional_rules;
    mask_t src_port_optional_rules;
    mask_t dst_port_optional_rules;
    mask_t src_prefix_optional_rules;
    mask_t dst_prefix_optional_rules;
    __u32  ingress_verdict;
};

struct tx_config {
    __u32 tcp_reset_mode;
    __u32 tcp_reset_egress_ifindex;
    __u32 tcp_reset_vlan_mode;
    __u32 tcp_reset_failure_verdict;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

/* XDP metadata for XSK-redirected packets (8 bytes). */
struct xsk_meta {
    __u32 rule_id;
    __u16 action;
    __u16 reserved;
};

/* Event output to userspace via ringbuf (32 bytes, no padding). */
struct rule_event {
    __u64 timestamp_ns;  /*  0 */
    __u32 rule_id;       /*  8 */
    __u32 pkt_conds;     /* 12 */
    __u32 sip;           /* 16 */
    __u32 dip;           /* 20 */
    __u16 action;        /* 24 */
    __u16 sport;         /* 26 */
    __u16 dport;         /* 28 */
    __u8  verdict;       /* 30 */
    __u8  ip_proto;      /* 31 */
} __attribute__((packed));

enum stat_idx {
    STAT_RX_PACKETS = 0,
    STAT_PARSE_FAILED,
    STAT_RULE_CANDIDATES,
    STAT_MATCHED_RULES,
    STAT_RINGBUF_DROPPED,
    STAT_XDP_TX,
    STAT_XSK_TX,
    STAT_TX_FAILED,
    STAT_XSK_FAILED,
    STAT_XSK_META_FAILED,
    STAT_XSK_REDIRECT_FAILED,
    STAT_REDIRECT_TX,
    STAT_REDIRECT_FAILED,
    STAT_FIB_LOOKUP_FAILED,
    STAT_COUNT,
};

#endif
