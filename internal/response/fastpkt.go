package response

import (
	"encoding/binary"
	"fmt"
)

const (
	fastpktEthernetHeaderLen = 14
	fastpktIPv4HeaderMinLen  = 20
	fastpktICMPv4HeaderLen   = 8
	fastpktARPHeaderLen      = 28
	fastpktTCPHeaderMinLen   = 20
	fastpktUDPHeaderLen      = 8

	fastpktEtherTypeIPv4  = 0x0800
	fastpktEtherTypeARP   = 0x0806
	fastpktEtherTypeDot1Q = 0x8100

	fastpktIPProtoICMP = 1
	fastpktIPProtoTCP  = 6
	fastpktIPProtoUDP  = 17

	fastpktARPReply   = 2
	fastpktARPRequest = 1

	fastpktTCPSyn = 0x02
	fastpktTCPAck = 0x10
	fastpktTCPRst = 0x04
	fastpktTCPFin = 0x01
)

type fastpktEthernetFrame struct {
	srcMAC    [6]byte
	dstMAC    [6]byte
	etherType uint16
	payload   []byte
}

type fastpktTupleFrame struct {
	etherType uint16
	payload   []byte
}

type fastpktIPv4Packet struct {
	id       uint16
	protocol uint8
	src      [4]byte
	dst      [4]byte
	payload  []byte
}

type fastpktICMPv4Packet struct {
	typ     uint8
	code    uint8
	id      uint16
	seq     uint16
	payload []byte
}

type fastpktARPPacket struct {
	operation uint16
	srcHW     [6]byte
	srcProt   [4]byte
	dstHW     [6]byte
	dstProt   [4]byte
}

type fastpktTCPPacket struct {
	srcPort uint16
	dstPort uint16
	seq     uint32
	flags   uint8
	payload []byte
}

type fastpktUDPPacket struct {
	srcPort uint16
	dstPort uint16
	payload []byte
}

func parseICMPEthernetFrame(frame []byte, context string) (fastpktEthernetFrame, fastpktIPv4Packet, fastpktICMPv4Packet, error) {
	eth, err := parseEthernetFrame(frame)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktICMPv4Packet{}, err
	}
	ip4, err := parseIPv4Packet(eth.payload, context)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktICMPv4Packet{}, err
	}
	if ip4.protocol != fastpktIPProtoICMP {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktICMPv4Packet{}, fmt.Errorf("%s: icmp layer missing", context)
	}
	icmp, err := parseICMPv4Packet(ip4.payload, context)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktICMPv4Packet{}, err
	}
	return eth, ip4, icmp, nil
}

func parseICMPIPv4FromEthernet(frame []byte, context string) (fastpktIPv4Packet, fastpktICMPv4Packet, error) {
	_, ip4, icmp, err := parseICMPEthernetFrame(frame, context)
	return ip4, icmp, err
}

func parseARPEthernetFrame(frame []byte, context string) (fastpktEthernetFrame, fastpktARPPacket, error) {
	eth, err := parseEthernetFrame(frame)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktARPPacket{}, err
	}
	if eth.etherType != fastpktEtherTypeARP {
		return fastpktEthernetFrame{}, fastpktARPPacket{}, fmt.Errorf("%s: arp layer missing", context)
	}
	arp, err := parseARPPacket(eth.payload)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktARPPacket{}, fmt.Errorf("%s: %w", context, err)
	}
	return eth, arp, nil
}

func parseTCPEthernetFrame(frame []byte, context string) (fastpktEthernetFrame, fastpktIPv4Packet, fastpktTCPPacket, error) {
	eth, err := parseEthernetFrame(frame)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktTCPPacket{}, err
	}
	ip4, err := parseIPv4Packet(eth.payload, context)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktTCPPacket{}, err
	}
	if ip4.protocol != fastpktIPProtoTCP {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktTCPPacket{}, fmt.Errorf("%s: tcp layer missing", context)
	}
	tcp, err := parseTCPPacket(ip4.payload, context)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktTCPPacket{}, err
	}
	return eth, ip4, tcp, nil
}

func parseUDPEthernetFrame(frame []byte, context string) (fastpktEthernetFrame, fastpktIPv4Packet, fastpktUDPPacket, error) {
	eth, err := parseEthernetFrame(frame)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktUDPPacket{}, err
	}
	ip4, err := parseIPv4Packet(eth.payload, context)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktUDPPacket{}, err
	}
	if ip4.protocol != fastpktIPProtoUDP {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktUDPPacket{}, fmt.Errorf("%s: udp layer missing", context)
	}
	udp, err := parseUDPPacket(ip4.payload)
	if err != nil {
		return fastpktEthernetFrame{}, fastpktIPv4Packet{}, fastpktUDPPacket{}, fmt.Errorf("%s: %w", context, err)
	}
	return eth, ip4, udp, nil
}

func parseEthernetFrame(frame []byte) (fastpktEthernetFrame, error) {
	if len(frame) < fastpktEthernetHeaderLen {
		return fastpktEthernetFrame{}, fmt.Errorf("parse ethernet frame: frame too short")
	}

	var eth fastpktEthernetFrame
	copy(eth.dstMAC[:], frame[0:6])
	copy(eth.srcMAC[:], frame[6:12])
	eth.etherType = binary.BigEndian.Uint16(frame[12:14])
	if eth.etherType == fastpktEtherTypeDot1Q {
		return fastpktEthernetFrame{}, fmt.Errorf("parse ethernet frame: vlan frames are not supported")
	}
	eth.payload = frame[fastpktEthernetHeaderLen:]
	return eth, nil
}

func parseTupleEthernetFrame(frame []byte) (fastpktTupleFrame, error) {
	if len(frame) < fastpktEthernetHeaderLen {
		return fastpktTupleFrame{}, fmt.Errorf("parse ethernet frame: frame too short")
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case fastpktEtherTypeDot1Q:
		if len(frame) < fastpktEthernetHeaderLen+4 {
			return fastpktTupleFrame{}, fmt.Errorf("parse ethernet frame: vlan header too short")
		}
		innerEtherType := binary.BigEndian.Uint16(frame[16:18])
		if innerEtherType == fastpktEtherTypeDot1Q {
			return fastpktTupleFrame{}, fmt.Errorf("parse ethernet frame: stacked vlan frames are not supported")
		}
		return fastpktTupleFrame{
			etherType: innerEtherType,
			payload:   frame[18:],
		}, nil
	default:
		return fastpktTupleFrame{
			etherType: etherType,
			payload:   frame[fastpktEthernetHeaderLen:],
		}, nil
	}
}

func parseIPv4Packet(frame []byte, context string) (fastpktIPv4Packet, error) {
	if len(frame) < fastpktIPv4HeaderMinLen {
		return fastpktIPv4Packet{}, fmt.Errorf("%s: ipv4 layer missing", context)
	}
	if frame[0]>>4 != 4 {
		return fastpktIPv4Packet{}, fmt.Errorf("%s: ipv4 layer missing", context)
	}

	headerLen := int(frame[0]&0x0f) * 4
	if headerLen < fastpktIPv4HeaderMinLen || len(frame) < headerLen {
		return fastpktIPv4Packet{}, fmt.Errorf("%s: invalid ipv4 header", context)
	}
	totalLen := int(binary.BigEndian.Uint16(frame[2:4]))
	if totalLen < headerLen || len(frame) < totalLen {
		return fastpktIPv4Packet{}, fmt.Errorf("%s: invalid ipv4 total length", context)
	}

	var ip4 fastpktIPv4Packet
	ip4.id = binary.BigEndian.Uint16(frame[4:6])
	ip4.protocol = frame[9]
	copy(ip4.src[:], frame[12:16])
	copy(ip4.dst[:], frame[16:20])
	ip4.payload = frame[headerLen:totalLen]
	return ip4, nil
}

func parseICMPv4Packet(frame []byte, context string) (fastpktICMPv4Packet, error) {
	if len(frame) < fastpktICMPv4HeaderLen {
		return fastpktICMPv4Packet{}, fmt.Errorf("%s: icmp layer missing", context)
	}

	var icmp fastpktICMPv4Packet
	icmp.typ = frame[0]
	icmp.code = frame[1]
	icmp.id = binary.BigEndian.Uint16(frame[4:6])
	icmp.seq = binary.BigEndian.Uint16(frame[6:8])
	icmp.payload = frame[8:]
	return icmp, nil
}

func parseARPPacket(frame []byte) (fastpktARPPacket, error) {
	if len(frame) < fastpktARPHeaderLen {
		return fastpktARPPacket{}, fmt.Errorf("arp layer missing")
	}

	var arp fastpktARPPacket
	arp.operation = binary.BigEndian.Uint16(frame[6:8])
	copy(arp.srcHW[:], frame[8:14])
	copy(arp.srcProt[:], frame[14:18])
	copy(arp.dstHW[:], frame[18:24])
	copy(arp.dstProt[:], frame[24:28])
	return arp, nil
}

func parseTCPPacket(frame []byte, context string) (fastpktTCPPacket, error) {
	if len(frame) < fastpktTCPHeaderMinLen {
		return fastpktTCPPacket{}, fmt.Errorf("%s: tcp layer missing", context)
	}

	headerLen := int(frame[12]>>4) * 4
	if headerLen < fastpktTCPHeaderMinLen || len(frame) < headerLen {
		return fastpktTCPPacket{}, fmt.Errorf("%s: invalid tcp header", context)
	}

	var tcp fastpktTCPPacket
	tcp.srcPort = binary.BigEndian.Uint16(frame[0:2])
	tcp.dstPort = binary.BigEndian.Uint16(frame[2:4])
	tcp.seq = binary.BigEndian.Uint32(frame[4:8])
	tcp.flags = frame[13]
	tcp.payload = frame[headerLen:]
	return tcp, nil
}

func parseUDPPacket(frame []byte) (fastpktUDPPacket, error) {
	if len(frame) < fastpktUDPHeaderLen {
		return fastpktUDPPacket{}, fmt.Errorf("udp layer missing")
	}

	udpLen := int(binary.BigEndian.Uint16(frame[4:6]))
	if udpLen < fastpktUDPHeaderLen || len(frame) < udpLen {
		return fastpktUDPPacket{}, fmt.Errorf("invalid udp header")
	}

	return fastpktUDPPacket{
		srcPort: binary.BigEndian.Uint16(frame[0:2]),
		dstPort: binary.BigEndian.Uint16(frame[2:4]),
		payload: frame[fastpktUDPHeaderLen:udpLen],
	}, nil
}

func buildICMPEchoReplyFrame(eth fastpktEthernetFrame, ip4 fastpktIPv4Packet, icmp fastpktICMPv4Packet) []byte {
	return buildICMPEchoReplyFrameToBuffer(nil, eth, ip4, icmp)
}

func buildICMPEchoReplyFrameToBuffer(dst []byte, eth fastpktEthernetFrame, ip4 fastpktIPv4Packet, icmp fastpktICMPv4Packet) []byte {
	icmpLen := fastpktICMPv4HeaderLen + len(icmp.payload)
	ipLen := fastpktIPv4HeaderMinLen + icmpLen
	out := reserveFastpktBuffer(dst, fastpktEthernetHeaderLen+ipLen)

	copy(out[0:6], eth.srcMAC[:])
	copy(out[6:12], eth.dstMAC[:])
	binary.BigEndian.PutUint16(out[12:14], fastpktEtherTypeIPv4)

	ipOffset := fastpktEthernetHeaderLen
	writeIPv4Header(out[ipOffset:ipOffset+fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoICMP, ipLen)

	icmpOffset := ipOffset + fastpktIPv4HeaderMinLen
	out[icmpOffset] = 0
	out[icmpOffset+1] = 0
	binary.BigEndian.PutUint16(out[icmpOffset+4:icmpOffset+6], icmp.id)
	binary.BigEndian.PutUint16(out[icmpOffset+6:icmpOffset+8], icmp.seq)
	copy(out[icmpOffset+8:], icmp.payload)
	binary.BigEndian.PutUint16(out[icmpOffset+2:icmpOffset+4], checksum(out[icmpOffset:icmpOffset+icmpLen]))

	return out
}

func buildICMPEchoReplyIPv4Packet(ip4 fastpktIPv4Packet, icmp fastpktICMPv4Packet) []byte {
	return buildICMPEchoReplyIPv4PacketToBuffer(nil, ip4, icmp)
}

func buildICMPEchoReplyIPv4PacketToBuffer(dst []byte, ip4 fastpktIPv4Packet, icmp fastpktICMPv4Packet) []byte {
	icmpLen := fastpktICMPv4HeaderLen + len(icmp.payload)
	ipLen := fastpktIPv4HeaderMinLen + icmpLen
	out := reserveFastpktBuffer(dst, ipLen)

	writeIPv4Header(out[:fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoICMP, ipLen)

	icmpOffset := fastpktIPv4HeaderMinLen
	out[icmpOffset] = 0
	out[icmpOffset+1] = 0
	binary.BigEndian.PutUint16(out[icmpOffset+4:icmpOffset+6], icmp.id)
	binary.BigEndian.PutUint16(out[icmpOffset+6:icmpOffset+8], icmp.seq)
	copy(out[icmpOffset+8:], icmp.payload)
	binary.BigEndian.PutUint16(out[icmpOffset+2:icmpOffset+4], checksum(out[icmpOffset:icmpOffset+icmpLen]))

	return out
}

func buildARPReplyFrame(eth fastpktEthernetFrame, arp fastpktARPPacket, hardwareAddr []byte) []byte {
	return buildARPReplyFrameToBuffer(nil, eth, arp, hardwareAddr)
}

func buildARPReplyFrameToBuffer(dst []byte, eth fastpktEthernetFrame, arp fastpktARPPacket, hardwareAddr []byte) []byte {
	out := reserveFastpktBuffer(dst, fastpktEthernetHeaderLen+fastpktARPHeaderLen)

	copy(out[0:6], eth.srcMAC[:])
	copy(out[6:12], hardwareAddr)
	binary.BigEndian.PutUint16(out[12:14], fastpktEtherTypeARP)

	arpOffset := fastpktEthernetHeaderLen
	binary.BigEndian.PutUint16(out[arpOffset:arpOffset+2], 1)
	binary.BigEndian.PutUint16(out[arpOffset+2:arpOffset+4], fastpktEtherTypeIPv4)
	out[arpOffset+4] = 6
	out[arpOffset+5] = 4
	binary.BigEndian.PutUint16(out[arpOffset+6:arpOffset+8], fastpktARPReply)
	copy(out[arpOffset+8:arpOffset+14], hardwareAddr)
	copy(out[arpOffset+14:arpOffset+18], arp.dstProt[:])
	copy(out[arpOffset+18:arpOffset+24], arp.srcHW[:])
	copy(out[arpOffset+24:arpOffset+28], arp.srcProt[:])

	return out
}

func buildTCPSynAckFrame(eth fastpktEthernetFrame, ip4 fastpktIPv4Packet, tcp fastpktTCPPacket, seq uint32) []byte {
	return buildTCPSynAckFrameToBuffer(nil, eth, ip4, tcp, seq)
}

func buildTCPSynAckFrameToBuffer(dst []byte, eth fastpktEthernetFrame, ip4 fastpktIPv4Packet, tcp fastpktTCPPacket, seq uint32) []byte {
	ipLen := fastpktIPv4HeaderMinLen + fastpktTCPHeaderMinLen
	out := reserveFastpktBuffer(dst, fastpktEthernetHeaderLen+ipLen)

	copy(out[0:6], eth.srcMAC[:])
	copy(out[6:12], eth.dstMAC[:])
	binary.BigEndian.PutUint16(out[12:14], fastpktEtherTypeIPv4)

	ipOffset := fastpktEthernetHeaderLen
	writeIPv4Header(out[ipOffset:ipOffset+fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoTCP, ipLen)

	tcpOffset := ipOffset + fastpktIPv4HeaderMinLen
	binary.BigEndian.PutUint16(out[tcpOffset:tcpOffset+2], tcp.dstPort)
	binary.BigEndian.PutUint16(out[tcpOffset+2:tcpOffset+4], tcp.srcPort)
	binary.BigEndian.PutUint32(out[tcpOffset+4:tcpOffset+8], seq)
	binary.BigEndian.PutUint32(out[tcpOffset+8:tcpOffset+12], tcp.seq+1)
	out[tcpOffset+12] = 5 << 4
	out[tcpOffset+13] = fastpktTCPSyn | fastpktTCPAck
	binary.BigEndian.PutUint16(out[tcpOffset+14:tcpOffset+16], 65535)
	binary.BigEndian.PutUint16(out[tcpOffset+16:tcpOffset+18], 0)
	binary.BigEndian.PutUint16(out[tcpOffset+18:tcpOffset+20], 0)
	binary.BigEndian.PutUint16(out[tcpOffset+16:tcpOffset+18], tcpChecksum(ip4.dst, ip4.src, out[tcpOffset:tcpOffset+fastpktTCPHeaderMinLen]))

	return out
}

func buildTCPSynAckIPv4PacketToBuffer(dst []byte, ip4 fastpktIPv4Packet, tcp fastpktTCPPacket, seq uint32) []byte {
	ipLen := fastpktIPv4HeaderMinLen + fastpktTCPHeaderMinLen
	out := reserveFastpktBuffer(dst, ipLen)

	writeIPv4Header(out[:fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoTCP, ipLen)

	tcpOffset := fastpktIPv4HeaderMinLen
	binary.BigEndian.PutUint16(out[tcpOffset:tcpOffset+2], tcp.dstPort)
	binary.BigEndian.PutUint16(out[tcpOffset+2:tcpOffset+4], tcp.srcPort)
	binary.BigEndian.PutUint32(out[tcpOffset+4:tcpOffset+8], seq)
	binary.BigEndian.PutUint32(out[tcpOffset+8:tcpOffset+12], tcp.seq+1)
	out[tcpOffset+12] = 5 << 4
	out[tcpOffset+13] = fastpktTCPSyn | fastpktTCPAck
	binary.BigEndian.PutUint16(out[tcpOffset+14:tcpOffset+16], 65535)
	binary.BigEndian.PutUint16(out[tcpOffset+16:tcpOffset+18], 0)
	binary.BigEndian.PutUint16(out[tcpOffset+18:tcpOffset+20], 0)
	binary.BigEndian.PutUint16(out[tcpOffset+16:tcpOffset+18], tcpChecksum(ip4.dst, ip4.src, out[tcpOffset:tcpOffset+fastpktTCPHeaderMinLen]))

	return out
}

func buildUDPEchoReplyFrameToBuffer(dst []byte, eth fastpktEthernetFrame, ip4 fastpktIPv4Packet, udp fastpktUDPPacket) []byte {
	udpLen := fastpktUDPHeaderLen + len(udp.payload)
	ipLen := fastpktIPv4HeaderMinLen + udpLen
	out := reserveFastpktBuffer(dst, fastpktEthernetHeaderLen+ipLen)

	copy(out[0:6], eth.srcMAC[:])
	copy(out[6:12], eth.dstMAC[:])
	binary.BigEndian.PutUint16(out[12:14], fastpktEtherTypeIPv4)

	ipOffset := fastpktEthernetHeaderLen
	writeIPv4Header(out[ipOffset:ipOffset+fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoUDP, ipLen)

	udpOffset := ipOffset + fastpktIPv4HeaderMinLen
	writeUDPHeader(out[udpOffset:udpOffset+fastpktUDPHeaderLen], udp.dstPort, udp.srcPort, udpLen)
	copy(out[udpOffset+fastpktUDPHeaderLen:], udp.payload)
	binary.BigEndian.PutUint16(out[udpOffset+6:udpOffset+8], udpChecksum(ip4.dst, ip4.src, out[udpOffset:udpOffset+udpLen]))

	return out
}

func buildUDPEchoReplyIPv4PacketToBuffer(dst []byte, ip4 fastpktIPv4Packet, udp fastpktUDPPacket) []byte {
	udpLen := fastpktUDPHeaderLen + len(udp.payload)
	ipLen := fastpktIPv4HeaderMinLen + udpLen
	out := reserveFastpktBuffer(dst, ipLen)

	writeIPv4Header(out[:fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoUDP, ipLen)

	udpOffset := fastpktIPv4HeaderMinLen
	writeUDPHeader(out[udpOffset:udpOffset+fastpktUDPHeaderLen], udp.dstPort, udp.srcPort, udpLen)
	copy(out[udpOffset+fastpktUDPHeaderLen:], udp.payload)
	binary.BigEndian.PutUint16(out[udpOffset+6:udpOffset+8], udpChecksum(ip4.dst, ip4.src, out[udpOffset:udpOffset+udpLen]))

	return out
}

func buildDNSRefusedFrameToBuffer(dst []byte, eth fastpktEthernetFrame, ip4 fastpktIPv4Packet, udp fastpktUDPPacket, query dnsRefusedQuery) []byte {
	dnsLen := dnsHeaderLen + len(query.question)
	udpLen := fastpktUDPHeaderLen + dnsLen
	ipLen := fastpktIPv4HeaderMinLen + udpLen
	out := reserveFastpktBuffer(dst, fastpktEthernetHeaderLen+ipLen)

	copy(out[0:6], eth.srcMAC[:])
	copy(out[6:12], eth.dstMAC[:])
	binary.BigEndian.PutUint16(out[12:14], fastpktEtherTypeIPv4)

	ipOffset := fastpktEthernetHeaderLen
	writeIPv4Header(out[ipOffset:ipOffset+fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoUDP, ipLen)

	udpOffset := ipOffset + fastpktIPv4HeaderMinLen
	writeUDPHeader(out[udpOffset:udpOffset+fastpktUDPHeaderLen], udp.dstPort, udp.srcPort, udpLen)

	dnsOffset := udpOffset + fastpktUDPHeaderLen
	binary.BigEndian.PutUint16(out[dnsOffset:dnsOffset+2], query.id)
	binary.BigEndian.PutUint16(out[dnsOffset+2:dnsOffset+4], dnsFlagQR|query.preserve|dnsRCodeRefused)
	binary.BigEndian.PutUint16(out[dnsOffset+4:dnsOffset+6], 1)
	copy(out[dnsOffset+dnsHeaderLen:], query.question)

	binary.BigEndian.PutUint16(out[udpOffset+6:udpOffset+8], udpChecksum(ip4.dst, ip4.src, out[udpOffset:udpOffset+udpLen]))

	return out
}

func buildDNSRefusedIPv4PacketToBuffer(dst []byte, ip4 fastpktIPv4Packet, udp fastpktUDPPacket, query dnsRefusedQuery) []byte {
	dnsLen := dnsHeaderLen + len(query.question)
	udpLen := fastpktUDPHeaderLen + dnsLen
	ipLen := fastpktIPv4HeaderMinLen + udpLen
	out := reserveFastpktBuffer(dst, ipLen)

	writeIPv4Header(out[:fastpktIPv4HeaderMinLen], ip4.dst, ip4.src, ip4.id, fastpktIPProtoUDP, ipLen)

	udpOffset := fastpktIPv4HeaderMinLen
	writeUDPHeader(out[udpOffset:udpOffset+fastpktUDPHeaderLen], udp.dstPort, udp.srcPort, udpLen)

	dnsOffset := udpOffset + fastpktUDPHeaderLen
	binary.BigEndian.PutUint16(out[dnsOffset:dnsOffset+2], query.id)
	binary.BigEndian.PutUint16(out[dnsOffset+2:dnsOffset+4], dnsFlagQR|query.preserve|dnsRCodeRefused)
	binary.BigEndian.PutUint16(out[dnsOffset+4:dnsOffset+6], 1)
	copy(out[dnsOffset+dnsHeaderLen:], query.question)

	binary.BigEndian.PutUint16(out[udpOffset+6:udpOffset+8], udpChecksum(ip4.dst, ip4.src, out[udpOffset:udpOffset+udpLen]))

	return out
}

func reserveFastpktBuffer(dst []byte, size int) []byte {
	if cap(dst) < size {
		return make([]byte, size)
	}
	dst = dst[:size]
	clear(dst)
	return dst
}

func writeIPv4Header(out []byte, src [4]byte, dst [4]byte, id uint16, protocol uint8, totalLen int) {
	out[0] = 0x45
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(out[4:6], id)
	binary.BigEndian.PutUint16(out[6:8], 0)
	out[8] = 64
	out[9] = protocol
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:fastpktIPv4HeaderMinLen]))
}

func writeUDPHeader(out []byte, srcPort uint16, dstPort uint16, totalLen int) {
	binary.BigEndian.PutUint16(out[0:2], srcPort)
	binary.BigEndian.PutUint16(out[2:4], dstPort)
	binary.BigEndian.PutUint16(out[4:6], uint16(totalLen))
	binary.BigEndian.PutUint16(out[6:8], 0)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(src [4]byte, dst [4]byte, segment []byte) uint16 {
	var sum uint32

	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(fastpktIPProtoTCP)
	sum += uint32(len(segment))

	for i := 0; i+1 < len(segment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i : i+2]))
	}
	if len(segment)%2 != 0 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(src [4]byte, dst [4]byte, segment []byte) uint16 {
	var sum uint32

	sum += uint32(binary.BigEndian.Uint16(src[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	sum += uint32(fastpktIPProtoUDP)
	sum += uint32(len(segment))

	for i := 0; i+1 < len(segment); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(segment[i : i+2]))
	}
	if len(segment)%2 != 0 {
		sum += uint32(segment[len(segment)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	result := ^uint16(sum)
	if result == 0 {
		return 0xffff
	}
	return result
}
