package response

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

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
	switch meta.Action {
	case ActionICMPEchoReply:
		return buildICMPEchoReply(frame)
	case ActionARPReply:
		return buildARPReply(frame, opts.HardwareAddr)
	case ActionTCPSynAck:
		return buildTCPSynAck(frame, opts.TCPSeq)
	default:
		return nil, fmt.Errorf("build response: unsupported action %d", meta.Action)
	}
}

func BuildICMPEchoReplyIPv4(frame []byte) ([]byte, error) {
	ip4, icmp, err := parseICMPIPv4Packet(frame)
	if err != nil {
		return nil, err
	}
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest || icmp.TypeCode.Code() != 0 {
		return nil, fmt.Errorf("build icmp echo reply: packet is not echo request")
	}

	outIP := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       ip4.Id,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    append(net.IP(nil), ip4.DstIP...),
		DstIP:    append(net.IP(nil), ip4.SrcIP...),
	}
	outICMP := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       icmp.Id,
		Seq:      icmp.Seq,
	}

	return serializeLayers(&outIP, &outICMP, gopacket.Payload(append([]byte(nil), icmp.Payload...)))
}

func buildICMPEchoReply(frame []byte) ([]byte, error) {
	eth, ip4, icmp, err := parseICMPFrame(frame)
	if err != nil {
		return nil, err
	}
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoRequest || icmp.TypeCode.Code() != 0 {
		return nil, fmt.Errorf("build icmp echo reply: packet is not echo request")
	}

	outEth := layers.Ethernet{
		SrcMAC:       append(net.HardwareAddr(nil), eth.DstMAC...),
		DstMAC:       append(net.HardwareAddr(nil), eth.SrcMAC...),
		EthernetType: layers.EthernetTypeIPv4,
	}
	outIP := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       ip4.Id,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    append(net.IP(nil), ip4.DstIP...),
		DstIP:    append(net.IP(nil), ip4.SrcIP...),
	}
	outICMP := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
		Id:       icmp.Id,
		Seq:      icmp.Seq,
	}

	return serializeLayers(&outEth, &outIP, &outICMP, gopacket.Payload(append([]byte(nil), icmp.Payload...)))
}

func buildARPReply(frame []byte, hardwareAddr net.HardwareAddr) ([]byte, error) {
	if len(hardwareAddr) != 6 {
		return nil, fmt.Errorf("build arp reply: hardware address is required")
	}

	eth, arp, err := parseARPFrame(frame)
	if err != nil {
		return nil, err
	}
	if arp.Operation != layers.ARPRequest {
		return nil, fmt.Errorf("build arp reply: packet is not arp request")
	}

	outEth := layers.Ethernet{
		SrcMAC:       append(net.HardwareAddr(nil), hardwareAddr...),
		DstMAC:       append(net.HardwareAddr(nil), eth.SrcMAC...),
		EthernetType: layers.EthernetTypeARP,
	}
	outARP := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   append([]byte(nil), hardwareAddr...),
		SourceProtAddress: append([]byte(nil), arp.DstProtAddress...),
		DstHwAddress:      append([]byte(nil), arp.SourceHwAddress...),
		DstProtAddress:    append([]byte(nil), arp.SourceProtAddress...),
	}

	return serializeLayers(&outEth, &outARP)
}

func buildTCPSynAck(frame []byte, seq uint32) ([]byte, error) {
	eth, ip4, tcp, err := parseTCPFrame(frame)
	if err != nil {
		return nil, err
	}
	if !tcp.SYN || tcp.ACK || tcp.RST || tcp.FIN {
		return nil, fmt.Errorf("build tcp syn ack: packet is not initial syn")
	}
	if len(tcp.Payload) > 0 {
		return nil, fmt.Errorf("build tcp syn ack: syn payload is not supported")
	}
	if seq == 0 {
		seq = 1
	}

	outEth := layers.Ethernet{
		SrcMAC:       append(net.HardwareAddr(nil), eth.DstMAC...),
		DstMAC:       append(net.HardwareAddr(nil), eth.SrcMAC...),
		EthernetType: layers.EthernetTypeIPv4,
	}
	outIP := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       ip4.Id,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    append(net.IP(nil), ip4.DstIP...),
		DstIP:    append(net.IP(nil), ip4.SrcIP...),
	}
	outTCP := layers.TCP{
		SrcPort: tcp.DstPort,
		DstPort: tcp.SrcPort,
		Seq:     seq,
		Ack:     tcp.Seq + 1,
		SYN:     true,
		ACK:     true,
		Window:  65535,
	}
	if err := outTCP.SetNetworkLayerForChecksum(&outIP); err != nil {
		return nil, fmt.Errorf("build tcp syn ack: set checksum network layer: %w", err)
	}

	return serializeLayers(&outEth, &outIP, &outTCP)
}

func parseFrame(frame []byte) (gopacket.Packet, *layers.Ethernet, error) {
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		return nil, nil, fmt.Errorf("parse ethernet frame: %v", errLayer.Error())
	}
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil, fmt.Errorf("parse ethernet frame: ethernet layer missing")
	}
	eth, ok := ethLayer.(*layers.Ethernet)
	if !ok {
		return nil, nil, fmt.Errorf("parse ethernet frame: unexpected ethernet layer")
	}
	if packet.Layer(layers.LayerTypeDot1Q) != nil {
		return nil, nil, fmt.Errorf("parse ethernet frame: vlan frames are not supported")
	}
	return packet, eth, nil
}

func parseICMPFrame(frame []byte) (*layers.Ethernet, *layers.IPv4, *layers.ICMPv4, error) {
	packet, eth, err := parseFrame(frame)
	if err != nil {
		return nil, nil, nil, err
	}
	ip4, err := requireIPv4(packet, "build icmp echo reply")
	if err != nil {
		return nil, nil, nil, err
	}
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return nil, nil, nil, fmt.Errorf("build icmp echo reply: icmp layer missing")
	}
	icmp, ok := icmpLayer.(*layers.ICMPv4)
	if !ok {
		return nil, nil, nil, fmt.Errorf("build icmp echo reply: unexpected icmp layer")
	}
	return eth, ip4, icmp, nil
}

func parseICMPIPv4Packet(frame []byte) (*layers.IPv4, *layers.ICMPv4, error) {
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		return nil, nil, fmt.Errorf("parse ethernet frame: %v", errLayer.Error())
	}
	ip4, err := requireIPv4(packet, "build icmp echo reply")
	if err != nil {
		return nil, nil, err
	}
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		return nil, nil, fmt.Errorf("build icmp echo reply: icmp layer missing")
	}
	icmp, ok := icmpLayer.(*layers.ICMPv4)
	if !ok {
		return nil, nil, fmt.Errorf("build icmp echo reply: unexpected icmp layer")
	}
	return ip4, icmp, nil
}

func parseARPFrame(frame []byte) (*layers.Ethernet, *layers.ARP, error) {
	packet, eth, err := parseFrame(frame)
	if err != nil {
		return nil, nil, err
	}
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		return nil, nil, fmt.Errorf("build arp reply: arp layer missing")
	}
	arp, ok := arpLayer.(*layers.ARP)
	if !ok {
		return nil, nil, fmt.Errorf("build arp reply: unexpected arp layer")
	}
	return eth, arp, nil
}

func parseTCPFrame(frame []byte) (*layers.Ethernet, *layers.IPv4, *layers.TCP, error) {
	packet, eth, err := parseFrame(frame)
	if err != nil {
		return nil, nil, nil, err
	}
	ip4, err := requireIPv4(packet, "build tcp syn ack")
	if err != nil {
		return nil, nil, nil, err
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, nil, nil, fmt.Errorf("build tcp syn ack: tcp layer missing")
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil, nil, nil, fmt.Errorf("build tcp syn ack: unexpected tcp layer")
	}
	return eth, ip4, tcp, nil
}

func requireIPv4(packet gopacket.Packet, context string) (*layers.IPv4, error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("%s: ipv4 layer missing", context)
	}
	ip4, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil, fmt.Errorf("%s: unexpected ipv4 layer", context)
	}
	return ip4, nil
}

func serializeLayers(items ...gopacket.SerializableLayer) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, items...); err != nil {
		return nil, fmt.Errorf("serialize response frame: %w", err)
	}
	return buffer.Bytes(), nil
}
