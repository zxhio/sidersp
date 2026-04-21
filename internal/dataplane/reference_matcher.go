//go:build linux

package dataplane

import (
	"net/netip"
	"slices"
	"strings"

	"sidersp/internal/rule"
)

const vlanNone = 0xFFFF

// refPacket is a simplified packet representation for the reference matcher.
type refPacket struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	VLAN     uint16 // 0xFFFF = no VLAN
	IPProto  uint8  // 6=TCP, 17=UDP, 1=ICMP
	ICMPType uint8
	ICMPCode uint8
	ARPOp    uint16
}

// refMatchResult is the output of the reference matcher.
type refMatchResult struct {
	Matched  bool
	RuleID   int
	Priority int
	Action   string
}

// refMatch matches a packet against rules using pure semantic logic:
// sort rules by priority, check each condition directly, first match wins.
// This is the ground truth for verifying BPF kernel behavior.
func refMatch(rules []rule.Rule, pkt refPacket) refMatchResult {
	sorted := make([]rule.Rule, len(rules))
	copy(sorted, rules)
	slices.SortFunc(sorted, func(a, b rule.Rule) int {
		if a.Priority != b.Priority {
			return a.Priority - b.Priority
		}
		return a.ID - b.ID
	})

	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		if refRuleMatches(r, pkt) {
			return refMatchResult{
				Matched:  true,
				RuleID:   r.ID,
				Priority: r.Priority,
				Action:   r.Response.Action,
			}
		}
	}

	return refMatchResult{}
}

// refRuleMatches checks if a single rule matches a packet by evaluating
// each condition directly (no bitmaps, no indexes).
func refRuleMatches(r rule.Rule, pkt refPacket) bool {
	switch strings.ToLower(strings.TrimSpace(r.Match.Protocol)) {
	case "tcp":
		if pkt.IPProto != 6 {
			return false
		}
	case "udp":
		if pkt.IPProto != 17 {
			return false
		}
	case "icmp":
		if pkt.IPProto != 1 {
			return false
		}
	case "arp":
		if pkt.ARPOp == 0 {
			return false
		}
	case "":
	}

	tf := r.Match.TCPFlags
	if tf.SYN != nil && *tf.SYN && pkt.TCPFlags&0x02 == 0 {
		return false
	}
	if tf.ACK != nil && *tf.ACK && pkt.TCPFlags&0x10 == 0 {
		return false
	}
	if tf.RST != nil && *tf.RST && pkt.TCPFlags&0x04 == 0 {
		return false
	}
	if tf.FIN != nil && *tf.FIN && pkt.TCPFlags&0x01 == 0 {
		return false
	}
	if tf.PSH != nil && *tf.PSH && pkt.TCPFlags&0x08 == 0 {
		return false
	}

	if r.Match.ICMP != nil {
		switch strings.ToLower(strings.TrimSpace(r.Match.ICMP.Type)) {
		case "echo_request":
			if pkt.ICMPType != 8 || pkt.ICMPCode != 0 {
				return false
			}
		case "echo_reply":
			if pkt.ICMPType != 0 || pkt.ICMPCode != 0 {
				return false
			}
		}
	}

	if r.Match.ARP != nil {
		switch strings.ToLower(strings.TrimSpace(r.Match.ARP.Operation)) {
		case "request":
			if pkt.ARPOp != 1 {
				return false
			}
		case "reply":
			if pkt.ARPOp != 2 {
				return false
			}
		}
	}

	// VLAN condition
	if len(r.Match.VLANs) > 0 {
		if pkt.VLAN == vlanNone {
			return false // Packet has no VLAN but rule requires one
		}
		found := false
		for _, v := range r.Match.VLANs {
			if uint16(v) == pkt.VLAN {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Source port condition
	if len(r.Match.SrcPorts) > 0 {
		found := false
		for _, p := range r.Match.SrcPorts {
			if uint16(p) == pkt.SrcPort {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Destination port condition
	if len(r.Match.DstPorts) > 0 {
		found := false
		for _, p := range r.Match.DstPorts {
			if uint16(p) == pkt.DstPort {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Source prefix condition
	if len(r.Match.SrcPrefixes) > 0 {
		found := false
		for _, raw := range r.Match.SrcPrefixes {
			pfx, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			if pfx.Contains(pkt.SrcIP) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Destination prefix condition
	if len(r.Match.DstPrefixes) > 0 {
		found := false
		for _, raw := range r.Match.DstPrefixes {
			pfx, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			if pfx.Contains(pkt.DstIP) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}
