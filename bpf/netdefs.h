/*
 * Compatibility protocol constants for values not emitted into vmlinux.h.
 *
 * IPPROTO_* is intentionally sourced from vmlinux.h when available there.
 */
#ifndef SIDERSP_BPF_NETDEFS_H
#define SIDERSP_BPF_NETDEFS_H

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

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ARPHRD_ETHER
#define ARPHRD_ETHER 1
#endif

#ifndef VLAN_HLEN
#define VLAN_HLEN 4
#endif

#endif
