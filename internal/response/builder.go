package response

import (
	"fmt"
	"net"

	"sidersp/internal/rule"
)

const (
	ActionICMPEchoReply = rule.ActionICMPEchoReply
	ActionARPReply      = rule.ActionARPReply
	ActionTCPSynAck     = rule.ActionTCPSynAck
)

type BuildOptions struct {
	HardwareAddr net.HardwareAddr
	TCPSeq       uint32
}

func BuildResponseFrame(meta XSKMetadata, frame []byte, opts BuildOptions) ([]byte, error) {
	return BuildResponseFrameToBuffer(meta, frame, opts, nil)
}

func BuildResponseFrameToBuffer(meta XSKMetadata, frame []byte, opts BuildOptions, dst []byte) ([]byte, error) {
	switch meta.Action {
	case ActionICMPEchoReply:
		return buildICMPEchoReplyToBuffer(frame, dst)
	case ActionARPReply:
		return buildARPReplyToBuffer(frame, opts.HardwareAddr, dst)
	case ActionTCPSynAck:
		return buildTCPSynAckToBuffer(frame, opts.TCPSeq, dst)
	default:
		return nil, fmt.Errorf("build response: unsupported action %d", meta.Action)
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
