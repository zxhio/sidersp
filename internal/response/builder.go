package response

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"sidersp/internal/rule"
)

const (
	ActionICMPEchoReply = rule.ActionICMPEchoReply
	ActionARPReply      = rule.ActionARPReply
	ActionTCPSynAck     = rule.ActionTCPSynAck
	ActionUDPEchoReply  = rule.ActionUDPEchoReply
	ActionDNSRefused    = rule.ActionDNSRefused
	ActionDNSSinkhole   = rule.ActionDNSSinkhole
)

type BuildOptions struct {
	HardwareAddr net.HardwareAddr
	TCPSeq       uint32
	RuleConfigs  *RuleConfigStore
}

var errResponseRequiresEthernetFraming = errors.New("response requires ethernet framing")

func BuildResponseFrame(meta XSKMetadata, frame []byte, opts BuildOptions) ([]byte, error) {
	return BuildResponseFrameToBuffer(meta, frame, opts, nil)
}

func BuildResponseIPv4Packet(meta XSKMetadata, frame []byte, opts BuildOptions) ([]byte, error) {
	return BuildResponseIPv4PacketToBuffer(meta, frame, opts, nil)
}

func BuildResponseFrameToBuffer(meta XSKMetadata, frame []byte, opts BuildOptions, dst []byte) ([]byte, error) {
	switch meta.Action {
	case ActionICMPEchoReply:
		return buildICMPEchoReplyToBuffer(frame, dst)
	case ActionARPReply:
		return buildARPReplyToBuffer(frame, opts.HardwareAddr, dst)
	case ActionTCPSynAck:
		return buildTCPSynAckToBuffer(frame, opts.TCPSeq, dst)
	case ActionUDPEchoReply:
		return buildUDPEchoReplyToBuffer(frame, dst)
	case ActionDNSRefused:
		return buildDNSRefusedToBuffer(frame, dst)
	case ActionDNSSinkhole:
		return buildDNSSinkholeToBuffer(meta.RuleID, frame, opts.RuleConfigs, dst)
	default:
		return nil, fmt.Errorf("build response: unsupported action %d", meta.Action)
	}
}

func BuildResponseIPv4PacketToBuffer(meta XSKMetadata, frame []byte, opts BuildOptions, dst []byte) ([]byte, error) {
	switch meta.Action {
	case ActionICMPEchoReply:
		return BuildICMPEchoReplyIPv4ToBuffer(frame, dst)
	case ActionTCPSynAck:
		return buildTCPSynAckIPv4ToBuffer(frame, opts.TCPSeq, dst)
	case ActionUDPEchoReply:
		return buildUDPEchoReplyIPv4ToBuffer(frame, dst)
	case ActionDNSRefused:
		return buildDNSRefusedIPv4ToBuffer(frame, dst)
	case ActionDNSSinkhole:
		return buildDNSSinkholeIPv4ToBuffer(meta.RuleID, frame, opts.RuleConfigs, dst)
	case ActionARPReply:
		return nil, fmt.Errorf("build response ipv4 packet: %w for action %d", errResponseRequiresEthernetFraming, meta.Action)
	default:
		return nil, fmt.Errorf("build response ipv4 packet: unsupported action %d", meta.Action)
	}
}

func BuildICMPEchoReplyIPv4(frame []byte) ([]byte, error) {
	return BuildICMPEchoReplyIPv4ToBuffer(frame, nil)
}

func BuildICMPEchoReplyIPv4ToBuffer(frame []byte, dst []byte) ([]byte, error) {
	ip4, icmp, err := parseICMPIPv4FromEthernet(frame, "build icmp echo reply")
	if err != nil {
		return nil, err
	}
	if icmp.typ != 8 || icmp.code != 0 {
		return nil, fmt.Errorf("build icmp echo reply: packet is not echo request")
	}

	return buildICMPEchoReplyIPv4PacketToBuffer(dst, ip4, icmp), nil
}

func buildICMPEchoReply(frame []byte) ([]byte, error) {
	return buildICMPEchoReplyToBuffer(frame, nil)
}

func buildICMPEchoReplyToBuffer(frame []byte, dst []byte) ([]byte, error) {
	eth, ip4, icmp, err := parseICMPEthernetFrame(frame, "build icmp echo reply")
	if err != nil {
		return nil, err
	}
	if icmp.typ != 8 || icmp.code != 0 {
		return nil, fmt.Errorf("build icmp echo reply: packet is not echo request")
	}

	return buildICMPEchoReplyFrameToBuffer(dst, eth, ip4, icmp), nil
}

func buildARPReply(frame []byte, hardwareAddr net.HardwareAddr) ([]byte, error) {
	return buildARPReplyToBuffer(frame, hardwareAddr, nil)
}

func buildARPReplyToBuffer(frame []byte, hardwareAddr net.HardwareAddr, dst []byte) ([]byte, error) {
	if len(hardwareAddr) != 6 {
		return nil, fmt.Errorf("build arp reply: hardware address is required")
	}

	eth, arp, err := parseARPEthernetFrame(frame, "build arp reply")
	if err != nil {
		return nil, err
	}
	if arp.operation != fastpktARPRequest {
		return nil, fmt.Errorf("build arp reply: packet is not arp request")
	}

	return buildARPReplyFrameToBuffer(dst, eth, arp, hardwareAddr), nil
}

func buildTCPSynAck(frame []byte, seq uint32) ([]byte, error) {
	return buildTCPSynAckToBuffer(frame, seq, nil)
}

func buildTCPSynAckToBuffer(frame []byte, seq uint32, dst []byte) ([]byte, error) {
	eth, ip4, tcp, err := parseTCPEthernetFrame(frame, "build tcp syn ack")
	if err != nil {
		return nil, err
	}
	if tcp.flags&fastpktTCPSyn == 0 || tcp.flags&(fastpktTCPAck|fastpktTCPRst|fastpktTCPFin) != 0 {
		return nil, fmt.Errorf("build tcp syn ack: packet is not initial syn")
	}
	if len(tcp.payload) > 0 {
		return nil, fmt.Errorf("build tcp syn ack: syn payload is not supported")
	}
	if seq == 0 {
		seq = 1
	}

	return buildTCPSynAckFrameToBuffer(dst, eth, ip4, tcp, seq), nil
}

func buildTCPSynAckIPv4ToBuffer(frame []byte, seq uint32, dst []byte) ([]byte, error) {
	_, ip4, tcp, err := parseTCPEthernetFrame(frame, "build tcp syn ack")
	if err != nil {
		return nil, err
	}
	if tcp.flags&fastpktTCPSyn == 0 || tcp.flags&(fastpktTCPAck|fastpktTCPRst|fastpktTCPFin) != 0 {
		return nil, fmt.Errorf("build tcp syn ack: packet is not initial syn")
	}
	if len(tcp.payload) > 0 {
		return nil, fmt.Errorf("build tcp syn ack: syn payload is not supported")
	}
	if seq == 0 {
		seq = 1
	}

	return buildTCPSynAckIPv4PacketToBuffer(dst, ip4, tcp, seq), nil
}

func buildUDPEchoReply(frame []byte) ([]byte, error) {
	return buildUDPEchoReplyToBuffer(frame, nil)
}

func buildUDPEchoReplyToBuffer(frame []byte, dst []byte) ([]byte, error) {
	eth, ip4, udp, err := parseUDPEthernetFrame(frame, "build udp echo reply")
	if err != nil {
		return nil, err
	}

	return buildUDPEchoReplyFrameToBuffer(dst, eth, ip4, udp), nil
}

func buildUDPEchoReplyIPv4ToBuffer(frame []byte, dst []byte) ([]byte, error) {
	_, ip4, udp, err := parseUDPEthernetFrame(frame, "build udp echo reply")
	if err != nil {
		return nil, err
	}

	return buildUDPEchoReplyIPv4PacketToBuffer(dst, ip4, udp), nil
}

func buildDNSRefused(frame []byte) ([]byte, error) {
	return buildDNSRefusedToBuffer(frame, nil)
}

func buildDNSRefusedToBuffer(frame []byte, dst []byte) ([]byte, error) {
	eth, ip4, udp, err := parseUDPEthernetFrame(frame, "build dns refused")
	if err != nil {
		return nil, err
	}

	query, err := parseDNSQuery(udp.payload, "build dns refused")
	if err != nil {
		return nil, err
	}

	return buildDNSRefusedFrameToBuffer(dst, eth, ip4, udp, query), nil
}

func buildDNSRefusedIPv4ToBuffer(frame []byte, dst []byte) ([]byte, error) {
	_, ip4, udp, err := parseUDPEthernetFrame(frame, "build dns refused")
	if err != nil {
		return nil, err
	}

	query, err := parseDNSQuery(udp.payload, "build dns refused")
	if err != nil {
		return nil, err
	}

	return buildDNSRefusedIPv4PacketToBuffer(dst, ip4, udp, query), nil
}

func buildDNSSinkholeToBuffer(ruleID uint32, frame []byte, configs *RuleConfigStore, dst []byte) ([]byte, error) {
	eth, ip4, udp, err := parseUDPEthernetFrame(frame, "build dns sinkhole")
	if err != nil {
		return nil, err
	}

	query, err := parseDNSSinkholeQuery(udp.payload)
	if err != nil {
		return nil, err
	}

	config, err := lookupDNSSinkholeConfig(ruleID, configs)
	if err != nil {
		return nil, err
	}

	return buildDNSSinkholeFrameToBuffer(dst, eth, ip4, udp, query, config), nil
}

func buildDNSSinkholeIPv4ToBuffer(ruleID uint32, frame []byte, configs *RuleConfigStore, dst []byte) ([]byte, error) {
	_, ip4, udp, err := parseUDPEthernetFrame(frame, "build dns sinkhole")
	if err != nil {
		return nil, err
	}

	query, err := parseDNSSinkholeQuery(udp.payload)
	if err != nil {
		return nil, err
	}

	config, err := lookupDNSSinkholeConfig(ruleID, configs)
	if err != nil {
		return nil, err
	}

	return buildDNSSinkholeIPv4PacketToBuffer(dst, ip4, udp, query, config), nil
}

const (
	dnsHeaderLen      = 12
	dnsFlagQR         = 1 << 15
	dnsFlagOpcodeMask = 0x7800
	dnsFlagRD         = 1 << 8
	dnsTypeA          = 1
	dnsClassIN        = 1
	dnsRCodeRefused   = 5
)

type dnsQuery struct {
	id       uint16
	preserve uint16
	name     []byte
	question []byte
	qtype    uint16
	qclass   uint16
}

func parseDNSQuery(payload []byte, context string) (dnsQuery, error) {
	if len(payload) < dnsHeaderLen {
		return dnsQuery{}, fmt.Errorf("%s: dns header missing", context)
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	if flags&dnsFlagQR != 0 {
		return dnsQuery{}, fmt.Errorf("%s: packet is not dns query", context)
	}
	if flags&dnsFlagOpcodeMask != 0 {
		return dnsQuery{}, fmt.Errorf("%s: only standard dns queries are supported", context)
	}

	if questions := binary.BigEndian.Uint16(payload[4:6]); questions != 1 {
		return dnsQuery{}, fmt.Errorf("%s: exactly one dns question is required", context)
	}

	nameEnd, questionEnd, err := scanDNSQuestion(payload, dnsHeaderLen)
	if err != nil {
		return dnsQuery{}, fmt.Errorf("%s: %w", context, err)
	}

	return dnsQuery{
		id:       binary.BigEndian.Uint16(payload[0:2]),
		preserve: flags & dnsFlagRD,
		name:     append([]byte(nil), payload[dnsHeaderLen:nameEnd]...),
		question: append([]byte(nil), payload[dnsHeaderLen:questionEnd]...),
		qtype:    binary.BigEndian.Uint16(payload[questionEnd-4 : questionEnd-2]),
		qclass:   binary.BigEndian.Uint16(payload[questionEnd-2 : questionEnd]),
	}, nil
}

func parseDNSSinkholeQuery(payload []byte) (dnsQuery, error) {
	query, err := parseDNSQuery(payload, "build dns sinkhole")
	if err != nil {
		return dnsQuery{}, err
	}
	if query.qtype != dnsTypeA {
		return dnsQuery{}, fmt.Errorf("build dns sinkhole: only dns A queries are supported")
	}
	if query.qclass != dnsClassIN {
		return dnsQuery{}, fmt.Errorf("build dns sinkhole: only dns class IN queries are supported")
	}
	return query, nil
}

func lookupDNSSinkholeConfig(ruleID uint32, configs *RuleConfigStore) (DNSSinkholeConfig, error) {
	config, ok := configs.DNSSinkholeConfig(ruleID)
	if !ok {
		return DNSSinkholeConfig{}, fmt.Errorf("build dns sinkhole: rule %d dns sinkhole config is not configured", ruleID)
	}
	return config, nil
}

func scanDNSQuestion(payload []byte, offset int) (int, int, error) {
	idx := offset
	for {
		if idx >= len(payload) {
			return 0, 0, fmt.Errorf("dns question is truncated")
		}
		labelLen := int(payload[idx])
		idx++
		switch {
		case labelLen == 0:
			if idx+4 > len(payload) {
				return 0, 0, fmt.Errorf("dns question is truncated")
			}
			return idx, idx + 4, nil
		case labelLen&0xc0 != 0:
			return 0, 0, fmt.Errorf("compressed dns names are not supported")
		case labelLen > 63:
			return 0, 0, fmt.Errorf("dns label length %d out of range", labelLen)
		case idx+labelLen > len(payload):
			return 0, 0, fmt.Errorf("dns question is truncated")
		default:
			idx += labelLen
		}
	}
}
