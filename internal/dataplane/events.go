package dataplane

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

type ruleEvent struct {
	TimestampNS uint64
	RuleID      uint32
	PktConds    uint32
	SIP         uint32
	DIP         uint32
	Action      uint16
	SPort       uint16
	DPort       uint16
	Verdict     uint8
	IPProto     uint8
}

func decodeRuleEvent(raw []byte) (ruleEvent, error) {
	if len(raw) != 32 {
		return ruleEvent{}, fmt.Errorf("unexpected event size %d", len(raw))
	}

	return ruleEvent{
		TimestampNS: binary.LittleEndian.Uint64(raw[0:8]),
		RuleID:      binary.LittleEndian.Uint32(raw[8:12]),
		PktConds:    binary.LittleEndian.Uint32(raw[12:16]),
		SIP:         binary.LittleEndian.Uint32(raw[16:20]),
		DIP:         binary.LittleEndian.Uint32(raw[20:24]),
		Action:      binary.LittleEndian.Uint16(raw[24:26]),
		SPort:       binary.LittleEndian.Uint16(raw[26:28]),
		DPort:       binary.LittleEndian.Uint16(raw[28:30]),
		Verdict:     raw[30],
		IPProto:     raw[31],
	}, nil
}

func ipv4String(v uint32) string {
	addr := [4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
	return netip.AddrFrom4(addr).String()
}

func actionName(action uint16) string {
	switch action {
	case actionNone:
		return "NONE"
	case actionAlert:
		return "ALERT"
	case actionTCPReset:
		return "TCP_RESET"
	case actionICMPEchoReply:
		return "ICMP_ECHO_REPLY"
	case actionARPReply:
		return "ARP_REPLY"
	case actionTCPSynAck:
		return "TCP_SYN_ACK"
	case actionICMPPortUnreachable:
		return "ICMP_PORT_UNREACHABLE"
	case actionICMPHostUnreachable:
		return "ICMP_HOST_UNREACHABLE"
	case actionICMPAdminProhibited:
		return "ICMP_ADMIN_PROHIBITED"
	case actionUDPEchoReply:
		return "UDP_ECHO_REPLY"
	case actionDNSRefused:
		return "DNS_REFUSED"
	case actionDNSSinkhole:
		return "DNS_SINKHOLE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", action)
	}
}

func conditionNames(mask uint32) string {
	if mask == 0 {
		return "NONE"
	}

	names := make([]string, 0, 19)
	if mask&condProtoTCP != 0 {
		names = append(names, "PROTO_TCP")
	}
	if mask&condProtoUDP != 0 {
		names = append(names, "PROTO_UDP")
	}
	if mask&condProtoICMP != 0 {
		names = append(names, "PROTO_ICMP")
	}
	if mask&condProtoARP != 0 {
		names = append(names, "PROTO_ARP")
	}
	if mask&condVLAN != 0 {
		names = append(names, "VLAN")
	}
	if mask&condSrcPrefix != 0 {
		names = append(names, "SRC_PREFIX")
	}
	if mask&condDstPrefix != 0 {
		names = append(names, "DST_PREFIX")
	}
	if mask&condSrcPort != 0 {
		names = append(names, "SRC_PORT")
	}
	if mask&condDstPort != 0 {
		names = append(names, "DST_PORT")
	}
	if mask&condTCPSYN != 0 {
		names = append(names, "TCP_SYN")
	}
	if mask&condTCPACK != 0 {
		names = append(names, "TCP_ACK")
	}
	if mask&condTCPRST != 0 {
		names = append(names, "TCP_RST")
	}
	if mask&condTCPFIN != 0 {
		names = append(names, "TCP_FIN")
	}
	if mask&condTCPPSH != 0 {
		names = append(names, "TCP_PSH")
	}
	if mask&condICMPEchoRequest != 0 {
		names = append(names, "ICMP_ECHO_REQUEST")
	}
	if mask&condICMPEchoReply != 0 {
		names = append(names, "ICMP_ECHO_REPLY")
	}
	if mask&condARPRequest != 0 {
		names = append(names, "ARP_REQUEST")
	}
	if mask&condARPReply != 0 {
		names = append(names, "ARP_REPLY")
	}
	if mask&condL4Payload != 0 {
		names = append(names, "L4_PAYLOAD")
	}

	return strings.Join(names, "|")
}
