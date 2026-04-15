/*
 * Shared data structures for the XDP data plane.
 *
 * Overall pipeline:
 *
 *   parse_packet() → index pre-filter → detect conditions
 *       → feature pre-filter → pick best rule → emit event
 *
 * See docs/xdp-flow.md for the full flow diagram.
 */
#ifndef SIDERSP_BPF_RULE_H
#define SIDERSP_BPF_RULE_H

#include <linux/types.h>
#include <linux/in6.h>

#include "mask.h"

#define VLAN_ID_NONE 0xffff

/*
 * Packet condition bits — set by detect_conditions() in prog.c.
 * Each bit indicates that the packet exhibits a particular property.
 * rule_meta.required_mask uses these bits to express which conditions
 * a rule requires for a match.
 *
 *   bit 0  COND_VLAN        packet carries a VLAN tag
 *   bit 1  COND_SRC_PREFIX  source IP matched a prefix in LPM trie
 *   bit 2  COND_DST_PREFIX  dest   IP matched a prefix in LPM trie
 *   bit 3  COND_SRC_PORT    sport != 0 (TCP/UDP)
 *   bit 4  COND_DST_PORT    dport != 0 (TCP/UDP)
 *   bit 5  COND_HTTP_METHOD payload starts with GET/POST/HEAD
 *   bit 6  COND_HTTP_11     payload contains "HTTP/1.1"
 *   bit 7  COND_TCP_SYN     TCP SYN flag set
 */
#define COND_VLAN         (1U << 0)
#define COND_SRC_PREFIX   (1U << 1)
#define COND_DST_PREFIX   (1U << 2)
#define COND_SRC_PORT     (1U << 3)
#define COND_DST_PORT     (1U << 4)
#define COND_HTTP_METHOD  (1U << 5)
#define COND_HTTP_11      (1U << 6)
#define COND_TCP_SYN      (1U << 7)

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
    RULE_ACTION_NONE = 0,
    RULE_ACTION_RST = 1,
    RULE_ACTION_REPORT = 2,
};

/* Per-packet parsing result (stack-only, never shared with userspace). */
struct pkt_ctx {
    __u16 eth_proto;
    __u16 vlan_id;

    __u8 ip_version;
    __u8 ip_proto;

    union {
        struct {
            __be32 saddr;
            __be32 daddr;
        };
        struct {
            struct in6_addr saddr6;
            struct in6_addr daddr6;
        };
    };

    __u16 sport;
    __u16 dport;

    __u8 tcp_flags;
    __u16 payload_len;
    void *payload;
};

/*
 * Per-slot rule metadata (stored in rule_index_map, written by control plane).
 *
 * Final match check:
 *   (pkt_conds & rule->required_mask) == rule->required_mask
 */
struct rule_meta {
    __u32 rule_id;
    __u32 priority;
    __u32 enabled;
    __u32 required_mask;
    __u32 action;
};

struct global_cfg {
    mask_t all_enabled_rules;
};

struct ipv4_lpm_key {
    __u32 prefixlen;
    __be32 addr;
};

/* Event output to userspace via ringbuf (36 bytes, no padding). */
struct rule_event {
    __u64 timestamp_ns;
    __u32 rule_id;
    __u32 pkt_conds;
    __u32 action;
    __u32 sip;
    __u32 dip;
    __u16 sport;
    __u16 dport;
    __u8 tcp_flags;
    __u8 ip_proto;
    __u16 payload_len;
};

enum stat_idx {
    STAT_RX_PACKETS = 0,
    STAT_PARSE_FAILED,
    STAT_RULE_CANDIDATES,
    STAT_MATCHED_RULES,
    STAT_RINGBUF_DROPPED,
    STAT_COUNT,
};

#endif
