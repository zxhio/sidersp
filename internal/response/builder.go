package response

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

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
		return buildARPReplyToBuffer(meta.RuleID, frame, opts.HardwareAddr, opts.RuleConfigs, dst)
	case ActionTCPSynAck:
		return buildTCPSynAckToBuffer(meta.RuleID, frame, opts.RuleConfigs, dst)
	case ActionUDPEchoReply:
		return buildUDPEchoReplyToBuffer(frame, dst)
	case ActionDNSRefused:
		return buildDNSResponseToBuffer(meta.RuleID, frame, opts.RuleConfigs, "build dns refused", dst)
	case ActionDNSSinkhole:
		return buildDNSResponseToBuffer(meta.RuleID, frame, opts.RuleConfigs, "build dns sinkhole", dst)
	default:
		return nil, fmt.Errorf("build response: unsupported action %d", meta.Action)
	}
}

func BuildResponseIPv4PacketToBuffer(meta XSKMetadata, frame []byte, opts BuildOptions, dst []byte) ([]byte, error) {
	switch meta.Action {
	case ActionICMPEchoReply:
		return BuildICMPEchoReplyIPv4ToBuffer(frame, dst)
	case ActionTCPSynAck:
		return buildTCPSynAckIPv4ToBuffer(meta.RuleID, frame, opts.RuleConfigs, dst)
	case ActionUDPEchoReply:
		return buildUDPEchoReplyIPv4ToBuffer(frame, dst)
	case ActionDNSRefused:
		return buildDNSResponseIPv4ToBuffer(meta.RuleID, frame, opts.RuleConfigs, "build dns refused", dst)
	case ActionDNSSinkhole:
		return buildDNSResponseIPv4ToBuffer(meta.RuleID, frame, opts.RuleConfigs, "build dns sinkhole", dst)
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
	return buildARPReplyToBuffer(0, frame, hardwareAddr, nil, nil)
}

func buildARPReplyToBuffer(ruleID uint32, frame []byte, defaultHardwareAddr net.HardwareAddr, configs *RuleConfigStore, dst []byte) ([]byte, error) {
	eth, arp, err := parseARPEthernetFrame(frame, "build arp reply")
	if err != nil {
		return nil, err
	}
	if arp.operation != fastpktARPRequest {
		return nil, fmt.Errorf("build arp reply: packet is not arp request")
	}

	config, err := lookupARPReplyConfig(ruleID, defaultHardwareAddr, configs)
	if err != nil {
		return nil, err
	}

	return buildARPReplyFrameToBuffer(dst, eth, arp, config.HardwareAddr, config.SenderIPv4, config.HasSenderIPv4()), nil
}

func buildTCPSynAck(frame []byte) ([]byte, error) {
	return buildTCPSynAckToBuffer(0, frame, nil, nil)
}

func buildTCPSynAckToBuffer(ruleID uint32, frame []byte, configs *RuleConfigStore, dst []byte) ([]byte, error) {
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

	seq := lookupTCPSynAckSeq(ruleID, configs)

	return buildTCPSynAckFrameToBuffer(dst, eth, ip4, tcp, seq), nil
}

func buildTCPSynAckIPv4ToBuffer(ruleID uint32, frame []byte, configs *RuleConfigStore, dst []byte) ([]byte, error) {
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

	seq := lookupTCPSynAckSeq(ruleID, configs)

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
	return buildDNSResponseToBuffer(0, frame, nil, "build dns refused", nil)
}

func buildDNSResponseToBuffer(ruleID uint32, frame []byte, configs *RuleConfigStore, context string, dst []byte) ([]byte, error) {
	eth, ip4, udp, err := parseUDPEthernetFrame(frame, context)
	if err != nil {
		return nil, err
	}

	query, err := parseDNSQuery(udp.payload, context)
	if err != nil {
		return nil, err
	}

	config, err := lookupDNSResponseConfig(ruleID, configs, context)
	if err != nil {
		return nil, err
	}

	answerType, answers, err := selectDNSResponseAnswers(query, config, context)
	if err != nil {
		return nil, err
	}

	return buildDNSResponseFrameToBuffer(dst, eth, ip4, udp, query, config, answerType, answers), nil
}

func buildDNSResponseIPv4ToBuffer(ruleID uint32, frame []byte, configs *RuleConfigStore, context string, dst []byte) ([]byte, error) {
	_, ip4, udp, err := parseUDPEthernetFrame(frame, context)
	if err != nil {
		return nil, err
	}

	query, err := parseDNSQuery(udp.payload, context)
	if err != nil {
		return nil, err
	}

	config, err := lookupDNSResponseConfig(ruleID, configs, context)
	if err != nil {
		return nil, err
	}

	answerType, answers, err := selectDNSResponseAnswers(query, config, context)
	if err != nil {
		return nil, err
	}

	return buildDNSResponseIPv4PacketToBuffer(dst, ip4, udp, query, config, answerType, answers), nil
}

const (
	dnsHeaderLen      = 12
	dnsFlagQR         = 1 << 15
	dnsFlagOpcodeMask = 0x7800
	dnsFlagRD         = 1 << 8
	dnsRCodeServFail  = 2
	dnsRCodeNXDomain  = 3
	dnsRCodeRefused   = 5
	dnsTypeA          = 1
	dnsTypeAAAA       = 28
	dnsClassIN        = 1
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

func lookupDNSResponseConfig(ruleID uint32, configs *RuleConfigStore, context string) (DNSResponseConfig, error) {
	config, ok := configs.DNSResponseConfig(ruleID)
	if !ok {
		return DNSResponseConfig{}, fmt.Errorf("%s: rule %d dns response config is not configured", context, ruleID)
	}
	return config, nil
}

func selectDNSResponseAnswers(query dnsQuery, config DNSResponseConfig, context string) (uint16, []netip.Addr, error) {
	if len(config.AnswersV4) == 0 && len(config.AnswersV6) == 0 {
		return 0, nil, nil
	}
	if query.qclass != dnsClassIN {
		return 0, nil, fmt.Errorf("%s: only dns class IN queries are supported", context)
	}

	switch query.qtype {
	case dnsTypeA:
		if len(config.AnswersV4) == 0 {
			return 0, nil, fmt.Errorf("%s: dns A query has no configured answers", context)
		}
		return dnsTypeA, config.AnswersV4, nil
	case dnsTypeAAAA:
		if len(config.AnswersV6) == 0 {
			return 0, nil, fmt.Errorf("%s: dns AAAA query has no configured answers", context)
		}
		return dnsTypeAAAA, config.AnswersV6, nil
	default:
		return 0, nil, fmt.Errorf("%s: only dns A and AAAA queries are supported", context)
	}
}

func lookupARPReplyConfig(ruleID uint32, defaultHardwareAddr net.HardwareAddr, configs *RuleConfigStore) (ARPReplyConfig, error) {
	config := ARPReplyConfig{}
	if configs != nil {
		if override, ok := configs.ARPReplyConfig(ruleID); ok {
			config = override
		}
	}

	if !config.HasHardwareAddr() {
		if len(defaultHardwareAddr) != 6 {
			return ARPReplyConfig{}, fmt.Errorf("build arp reply: hardware address is required")
		}
		config.HardwareAddr = append(net.HardwareAddr(nil), defaultHardwareAddr...)
	}

	return config, nil
}

func lookupTCPSynAckSeq(ruleID uint32, configs *RuleConfigStore) uint32 {
	if configs != nil {
		if config, ok := configs.TCPSynAckConfig(ruleID); ok && config.TCPSeq != 0 {
			return config.TCPSeq
		}
	}
	return 1
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
