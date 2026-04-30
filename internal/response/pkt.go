package response

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	ethernetHeaderLen   = 14
	arpPacketLen        = 28
	minIPv4HeaderLen    = 20
	minICMPv4HeaderLen  = 8
	minTCPHeaderLen     = 20
	minUDPHeaderLen     = 8
	minEthernetFrameLen = 60
	maxIPv4Options      = 40
	maxTCPOptions       = 40
	ethernetARPFrameLen = ethernetHeaderLen + arpPacketLen

	serializeSmallLimit  = 128
	serializeMediumLimit = 512
	serializeLargeLimit  = 2048

	defaultIPv4TTL   = 64
	defaultTCPWindow = 65535
	icmpZeroCode     = 0

	icmpEchoReplyTypeCode = layers.ICMPv4TypeCode(uint16(layers.ICMPv4TypeEchoReply) << 8)
)

type Packet struct {
	layerType gopacket.LayerType

	eth  layers.Ethernet
	ip4  layers.IPv4
	icmp layers.ICMPv4
	arp  layers.ARP
	tcp  layers.TCP
	udp  layers.UDP
	dns  layers.DNS

	ip4Options [maxIPv4Options]layers.IPv4Option
	tcpOptions [maxTCPOptions]layers.TCPOption
}

type DecodeHook func(*Packet, gopacket.LayerType) error
type DecodeHooks map[gopacket.LayerType]DecodeHook

type decodable interface {
	DecodeFromBytes([]byte, gopacket.DecodeFeedback) error
	LayerType() gopacket.LayerType
}

func decodeLayerWithHook[T decodable](pkt *Packet, data []byte, layer T, hooks DecodeHooks) error {
	if err := layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return err
	}
	pkt.layerType = layer.LayerType()
	hook, ok := hooks[pkt.layerType]
	if ok && hook != nil {
		return hook(pkt, pkt.layerType)
	}
	return nil
}

func (p *Packet) Decode(frame []byte, hooks DecodeHooks, context string) error {
	p.reset()

	if err := decodeLayerWithHook(p, frame, &p.eth, hooks); err != nil {
		return fmt.Errorf("parse ethernet frame: %w", err)
	}
	if p.eth.EthernetType == layers.EthernetTypeDot1Q {
		return fmt.Errorf("parse ethernet frame: vlan frames are not supported")
	}
	return p.decodePayload(hooks, context)
}

func (p *Packet) decodePayload(hooks DecodeHooks, context string) error {
	switch p.eth.EthernetType {
	case layers.EthernetTypeARP:
		return p.decodeARP(hooks, context)
	case layers.EthernetTypeIPv4:
		return p.decodeIPv4Payload(hooks, context)
	}
	return fmt.Errorf("%s: unsupported ethernet type %d", context, p.eth.EthernetType)
}

func (p *Packet) decodeIPv4Payload(hooks DecodeHooks, context string) error {
	if err := p.decodeIPv4(hooks, context); err != nil {
		return err
	}
	switch p.ip4.Protocol {
	case layers.IPProtocolICMPv4:
		return p.decodeICMP(hooks, context)
	case layers.IPProtocolTCP:
		return p.decodeTCP(hooks, context)
	case layers.IPProtocolUDP:
		return p.decodeUDP(hooks, context)
	}
	return fmt.Errorf("%s: unsupported ipv4 protocol %d", context, p.ip4.Protocol)
}

func (p *Packet) reset() {
	*p = Packet{
		ip4Options: p.ip4Options,
		tcpOptions: p.tcpOptions,
	}
	p.ip4.Options = p.ip4Options[:0]
	p.tcp.Options = p.tcpOptions[:0]
}

func (p *Packet) decodeARP(hooks DecodeHooks, context string) error {
	if err := decodeLayerWithHook(p, p.eth.Payload, &p.arp, hooks); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

func (p *Packet) decodeICMP(hooks DecodeHooks, context string) error {
	if err := decodeLayerWithHook(p, p.ip4.Payload, &p.icmp, hooks); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

func (p *Packet) decodeTCP(hooks DecodeHooks, context string) error {
	p.tcp.Options = p.tcpOptions[:0]
	p.tcp.Padding = nil
	if err := decodeLayerWithHook(p, p.ip4.Payload, &p.tcp, hooks); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

func (p *Packet) decodeIPv4(hooks DecodeHooks, context string) error {
	p.ip4.Options = p.ip4Options[:0]
	p.ip4.Padding = nil
	if err := decodeLayerWithHook(p, p.eth.Payload, &p.ip4, hooks); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	return nil
}

func (p *Packet) decodeUDP(hooks DecodeHooks, context string) error {
	if err := decodeLayerWithHook(p, p.ip4.Payload, &p.udp, hooks); err != nil {
		return fmt.Errorf("%s: %w", context, err)
	}
	p.tryDecodeDNS(hooks, context)
	return nil
}

func (p *Packet) tryDecodeDNS(hooks DecodeHooks, context string) {
	payload := p.udp.Payload
	if !hasDNSPort(&p.udp) || !isDNSQueryHeader(payload) {
		return
	}

	prev := p.layerType
	if err := decodeLayerWithHook(p, payload, &p.dns, hooks); err != nil {
		p.layerType = prev
	}
}

func hasDNSPort(udp *layers.UDP) bool {
	return uint16(udp.SrcPort) == 53 || uint16(udp.DstPort) == 53
}

func isDNSQueryHeader(payload []byte) bool {
	if len(payload) < dnsHeaderLen {
		return false
	}
	if payload[2]&0x80 != 0 {
		return false
	}
	if payload[3]&0x70 != 0 {
		return false
	}
	if binary.BigEndian.Uint16(payload[6:8]) != 0 {
		return false
	}
	return true
}

func (p *Packet) fillTuple(result *ResponseResult) {
	switch p.layerType {
	case layers.LayerTypeICMPv4, layers.LayerTypeTCP, layers.LayerTypeUDP, layers.LayerTypeDNS:
		if len(p.ip4.SrcIP) >= 4 {
			result.SIP = binary.BigEndian.Uint32(p.ip4.SrcIP[:4])
		}
		if len(p.ip4.DstIP) >= 4 {
			result.DIP = binary.BigEndian.Uint32(p.ip4.DstIP[:4])
		}
		result.IPProto = uint8(p.ip4.Protocol)
		switch p.layerType {
		case layers.LayerTypeTCP:
			result.SPort = uint16(p.tcp.SrcPort)
			result.DPort = uint16(p.tcp.DstPort)
		case layers.LayerTypeUDP, layers.LayerTypeDNS:
			result.SPort = uint16(p.udp.SrcPort)
			result.DPort = uint16(p.udp.DstPort)
		}
	case layers.LayerTypeARP:
		if len(p.arp.SourceProtAddress) >= 4 {
			result.SIP = binary.BigEndian.Uint32(p.arp.SourceProtAddress[:4])
		}
		if len(p.arp.DstProtAddress) >= 4 {
			result.DIP = binary.BigEndian.Uint32(p.arp.DstProtAddress[:4])
		}
	}
}
