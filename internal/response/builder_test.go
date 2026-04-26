package response

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	testSrcMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	testDstMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	testHWAddr = net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
)

func TestBuildICMPEchoReply(t *testing.T) {
	t.Parallel()

	request := buildTestICMPEchoRequest(t)
	reply, err := BuildResponseFrame(XSKMetadata{Action: ActionICMPEchoReply}, request, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildResponseFrame() error = %v", err)
	}

	packet := parseTestPacket(t, reply)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

	if !sameMAC(eth.SrcMAC, testDstMAC) || !sameMAC(eth.DstMAC, testSrcMAC) {
		t.Fatalf("ethernet = %s -> %s, want swapped", eth.SrcMAC, eth.DstMAC)
	}
	if ip4.SrcIP.String() != "10.0.0.2" || ip4.DstIP.String() != "10.0.0.1" {
		t.Fatalf("ip = %s -> %s, want swapped", ip4.SrcIP, ip4.DstIP)
	}
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply || icmp.Id != 7 || icmp.Seq != 9 {
		t.Fatalf("icmp = type %d id %d seq %d, want echo_reply id=7 seq=9", icmp.TypeCode.Type(), icmp.Id, icmp.Seq)
	}
	if string(icmp.Payload) != "payload" {
		t.Fatalf("icmp payload = %q, want payload", string(icmp.Payload))
	}
}

func TestBuildICMPEchoReplyIPv4(t *testing.T) {
	t.Parallel()

	reply, err := BuildICMPEchoReplyIPv4(buildTestICMPEchoRequest(t))
	if err != nil {
		t.Fatalf("BuildICMPEchoReplyIPv4() error = %v", err)
	}

	packet := gopacket.NewPacket(reply, layers.LayerTypeIPv4, gopacket.Default)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmp := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

	if ip4.SrcIP.String() != "10.0.0.2" || ip4.DstIP.String() != "10.0.0.1" {
		t.Fatalf("ip = %s -> %s, want swapped", ip4.SrcIP, ip4.DstIP)
	}
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply || icmp.Id != 7 || icmp.Seq != 9 {
		t.Fatalf("icmp = type %d id %d seq %d, want echo_reply id=7 seq=9", icmp.TypeCode.Type(), icmp.Id, icmp.Seq)
	}
}

func TestBuildARPReply(t *testing.T) {
	t.Parallel()

	request := buildTestARPRequest(t)
	reply, err := BuildResponseFrame(XSKMetadata{Action: ActionARPReply}, request, BuildOptions{HardwareAddr: testHWAddr})
	if err != nil {
		t.Fatalf("BuildResponseFrame() error = %v", err)
	}

	packet := parseTestPacket(t, reply)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)

	if !sameMAC(eth.SrcMAC, testHWAddr) || !sameMAC(eth.DstMAC, testSrcMAC) {
		t.Fatalf("ethernet = %s -> %s, want responder -> requester", eth.SrcMAC, eth.DstMAC)
	}
	if arp.Operation != layers.ARPReply {
		t.Fatalf("arp operation = %d, want reply", arp.Operation)
	}
	if !sameMAC(arp.SourceHwAddress, testHWAddr) || !sameMAC(arp.DstHwAddress, testSrcMAC) {
		t.Fatalf("arp mac = %x -> %x, want responder -> requester", arp.SourceHwAddress, arp.DstHwAddress)
	}
	if net.IP(arp.SourceProtAddress).String() != "10.0.0.2" || net.IP(arp.DstProtAddress).String() != "10.0.0.1" {
		t.Fatalf("arp ip = %s -> %s, want target -> requester", net.IP(arp.SourceProtAddress), net.IP(arp.DstProtAddress))
	}
}

func TestBuildTCPSynAck(t *testing.T) {
	t.Parallel()

	request := buildTestTCPSyn(t)
	reply, err := BuildResponseFrame(XSKMetadata{Action: ActionTCPSynAck}, request, BuildOptions{TCPSeq: 1000})
	if err != nil {
		t.Fatalf("BuildResponseFrame() error = %v", err)
	}

	packet := parseTestPacket(t, reply)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

	if !sameMAC(eth.SrcMAC, testDstMAC) || !sameMAC(eth.DstMAC, testSrcMAC) {
		t.Fatalf("ethernet = %s -> %s, want swapped", eth.SrcMAC, eth.DstMAC)
	}
	if ip4.SrcIP.String() != "10.0.0.2" || ip4.DstIP.String() != "10.0.0.1" {
		t.Fatalf("ip = %s -> %s, want swapped", ip4.SrcIP, ip4.DstIP)
	}
	if tcp.SrcPort != 80 || tcp.DstPort != 12345 || !tcp.SYN || !tcp.ACK || tcp.Seq != 1000 || tcp.Ack != 43 {
		t.Fatalf("tcp = %+v, want 80->12345 syn-ack seq=1000 ack=43", tcp)
	}
}

func TestBuildUDPEchoReply(t *testing.T) {
	t.Parallel()

	request := buildTestUDPDatagram(t, 12345, 5353, []byte("udp-payload"))
	reply, err := BuildResponseFrame(XSKMetadata{Action: ActionUDPEchoReply}, request, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildResponseFrame() error = %v", err)
	}

	packet := parseTestPacket(t, reply)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	payload := packet.ApplicationLayer()

	if !sameMAC(eth.SrcMAC, testDstMAC) || !sameMAC(eth.DstMAC, testSrcMAC) {
		t.Fatalf("ethernet = %s -> %s, want swapped", eth.SrcMAC, eth.DstMAC)
	}
	if ip4.SrcIP.String() != "10.0.0.2" || ip4.DstIP.String() != "10.0.0.1" {
		t.Fatalf("ip = %s -> %s, want swapped", ip4.SrcIP, ip4.DstIP)
	}
	if udp.SrcPort != 5353 || udp.DstPort != 12345 {
		t.Fatalf("udp ports = %d -> %d, want 5353 -> 12345", udp.SrcPort, udp.DstPort)
	}
	if payload == nil || string(payload.Payload()) != "udp-payload" {
		t.Fatalf("udp payload = %q, want udp-payload", payload.Payload())
	}
}

func TestBuildDNSRefused(t *testing.T) {
	t.Parallel()

	request := buildTestDNSQuery(t, "example.org")
	reply, err := BuildResponseFrame(XSKMetadata{Action: ActionDNSRefused}, request, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildResponseFrame() error = %v", err)
	}

	packet := parseTestPacket(t, reply)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	dns := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)

	if !sameMAC(eth.SrcMAC, testDstMAC) || !sameMAC(eth.DstMAC, testSrcMAC) {
		t.Fatalf("ethernet = %s -> %s, want swapped", eth.SrcMAC, eth.DstMAC)
	}
	if ip4.SrcIP.String() != "10.0.0.2" || ip4.DstIP.String() != "10.0.0.1" {
		t.Fatalf("ip = %s -> %s, want swapped", ip4.SrcIP, ip4.DstIP)
	}
	if udp.SrcPort != 53 || udp.DstPort != 53000 {
		t.Fatalf("udp ports = %d -> %d, want 53 -> 53000", udp.SrcPort, udp.DstPort)
	}
	if !dns.QR || dns.ResponseCode != layers.DNSResponseCodeRefused {
		t.Fatalf("dns flags = qr:%v rcode:%v, want response refused", dns.QR, dns.ResponseCode)
	}
	if dns.ID != 0x1234 || len(dns.Questions) != 1 {
		t.Fatalf("dns id/questions = %d/%d, want 0x1234/1", dns.ID, len(dns.Questions))
	}
	if string(dns.Questions[0].Name) != "example.org" {
		t.Fatalf("dns question = %q, want example.org", string(dns.Questions[0].Name))
	}
	if len(dns.Answers) != 0 || len(dns.Authorities) != 0 || len(dns.Additionals) != 0 {
		t.Fatalf("dns records = answers:%d authorities:%d additionals:%d, want 0/0/0", len(dns.Answers), len(dns.Authorities), len(dns.Additionals))
	}
}

func TestBuildResponseFrameRejectsIncompatiblePackets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		meta  XSKMetadata
		frame []byte
		opts  BuildOptions
		want  string
	}{
		{
			name:  "icmp action rejects tcp",
			meta:  XSKMetadata{Action: ActionICMPEchoReply},
			frame: buildTestTCPSyn(t),
			want:  "icmp layer missing",
		},
		{
			name:  "arp action requires hardware address",
			meta:  XSKMetadata{Action: ActionARPReply},
			frame: buildTestARPRequest(t),
			want:  "hardware address is required",
		},
		{
			name:  "tcp syn ack rejects syn ack",
			meta:  XSKMetadata{Action: ActionTCPSynAck},
			frame: buildTestTCPPacket(t, true, true),
			want:  "not initial syn",
		},
		{
			name:  "tcp syn ack rejects syn payload",
			meta:  XSKMetadata{Action: ActionTCPSynAck},
			frame: buildTestTCPSynWithPayload(t),
			want:  "syn payload is not supported",
		},
		{
			name:  "icmp action rejects vlan",
			meta:  XSKMetadata{Action: ActionICMPEchoReply},
			frame: buildTestVLANICMPEchoRequest(t),
			want:  "vlan frames are not supported",
		},
		{
			name:  "udp echo reply rejects tcp",
			meta:  XSKMetadata{Action: ActionUDPEchoReply},
			frame: buildTestTCPSyn(t),
			want:  "udp layer missing",
		},
		{
			name:  "udp echo reply rejects vlan",
			meta:  XSKMetadata{Action: ActionUDPEchoReply},
			frame: buildTestVLANDNSQuery(t, "example.org"),
			want:  "vlan frames are not supported",
		},
		{
			name:  "dns refused rejects non dns udp payload",
			meta:  XSKMetadata{Action: ActionDNSRefused},
			frame: buildTestUDPDatagram(t, 12345, 53, []byte("not-dns")),
			want:  "dns header missing",
		},
		{
			name:  "dns refused rejects dns response",
			meta:  XSKMetadata{Action: ActionDNSRefused},
			frame: buildTestDNSResponse(t, "example.org"),
			want:  "packet is not dns query",
		},
		{
			name:  "dns refused rejects multi question query",
			meta:  XSKMetadata{Action: ActionDNSRefused},
			frame: buildTestDNSMultiQuestionQuery(t),
			want:  "exactly one dns question is required",
		},
		{
			name:  "dns refused rejects compressed question",
			meta:  XSKMetadata{Action: ActionDNSRefused},
			frame: buildTestDNSCompressedQuestion(t),
			want:  "compressed dns names are not supported",
		},
		{
			name:  "unknown action",
			meta:  XSKMetadata{Action: 99},
			frame: buildTestTCPSyn(t),
			want:  "unsupported action",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := BuildResponseFrame(tc.meta, tc.frame, tc.opts)
			if err == nil {
				t.Fatal("BuildResponseFrame() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildResponseFrame() error = %q, want %q", err, tc.want)
			}
		})
	}
}

func buildTestICMPEchoRequest(t testing.TB) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       7, Seq: 9,
	}
	return serializeTestLayers(t, eth, ip4, icmp, gopacket.Payload([]byte("payload")))
}

func buildTestVLANICMPEchoRequest(t testing.TB) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeDot1Q}
	vlan := &layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolICMPv4,
	}
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       7, Seq: 9,
	}
	return serializeTestLayers(t, eth, vlan, ip4, icmp, gopacket.Payload([]byte("payload")))
}

func buildTestARPRequest(t testing.TB) []byte {
	t.Helper()

	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: broadcast, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		Operation:       layers.ARPRequest,
		SourceHwAddress: testSrcMAC, SourceProtAddress: ip("10.0.0.1"),
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: ip("10.0.0.2"),
	}
	return serializeTestLayers(t, eth, arp)
}

func buildTestTCPSyn(t testing.TB) []byte {
	t.Helper()
	return buildTestTCPPacket(t, true, false)
}

func buildTestTCPSynWithPayload(t testing.TB) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345, DstPort: 80,
		Seq: 42, SYN: true, Window: 4096,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set tcp checksum layer: %v", err)
	}
	return serializeTestLayers(t, eth, ip4, tcp, gopacket.Payload([]byte("syn-data")))
}

func buildTestUDPDatagram(t testing.TB, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum layer: %v", err)
	}
	return serializeTestLayers(t, eth, ip4, udp, gopacket.Payload(payload))
}

func buildTestDNSQuery(t testing.TB, name string) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 53000,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum layer: %v", err)
	}
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           false,
		OpCode:       layers.DNSOpCodeQuery,
		RD:           true,
		Questions:    []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		QDCount:      1,
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		ResponseCode: layers.DNSResponseCodeNoErr,
	}
	return serializeTestLayers(t, eth, ip4, udp, dns)
}

func buildTestVLANDNSQuery(t testing.TB, name string) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeDot1Q}
	vlan := &layers.Dot1Q{VLANIdentifier: 100, Type: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 53000,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum layer: %v", err)
	}
	dns := &layers.DNS{
		ID:        0x1234,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		QDCount:   1,
	}
	return serializeTestLayers(t, eth, vlan, ip4, udp, dns)
}

func buildTestDNSResponse(t testing.TB, name string) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 53000,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum layer: %v", err)
	}
	dns := &layers.DNS{
		ID:           0x1234,
		QR:           true,
		OpCode:       layers.DNSOpCodeQuery,
		Questions:    []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		QDCount:      1,
		ResponseCode: layers.DNSResponseCodeNoErr,
	}
	return serializeTestLayers(t, eth, ip4, udp, dns)
}

func buildTestDNSMultiQuestionQuery(t testing.TB) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 53000,
		DstPort: 53,
	}
	if err := udp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set udp checksum layer: %v", err)
	}
	dns := &layers.DNS{
		ID:        0x1234,
		Questions: []layers.DNSQuestion{{Name: []byte("example.org"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}, {Name: []byte("example.net"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN}},
		QDCount:   2,
	}
	return serializeTestLayers(t, eth, ip4, udp, dns)
}

func buildTestDNSCompressedQuestion(t testing.TB) []byte {
	t.Helper()

	frame := buildTestDNSQuery(t, "example.org")
	out := append([]byte(nil), frame...)

	const (
		ethLen = 14
		ipLen  = 20
		udpLen = 8
	)
	dnsOffset := ethLen + ipLen + udpLen
	questionOffset := dnsOffset + dnsHeaderLen

	out[questionOffset] = 0xc0
	out[questionOffset+1] = 0x0c
	copy(out[questionOffset+2:], out[questionOffset+13:])

	newDNSLen := dnsHeaderLen + 2 + 4
	newUDPLen := udpLen + newDNSLen
	newIPLen := ipLen + newUDPLen

	binary.BigEndian.PutUint16(out[ethLen+2:ethLen+4], uint16(newIPLen))
	binary.BigEndian.PutUint16(out[ethLen+10:ethLen+12], 0)
	binary.BigEndian.PutUint16(out[ethLen+10:ethLen+12], checksum(out[ethLen:ethLen+ipLen]))
	binary.BigEndian.PutUint16(out[ethLen+ipLen+4:ethLen+ipLen+6], uint16(newUDPLen))
	binary.BigEndian.PutUint16(out[ethLen+ipLen+6:ethLen+ipLen+8], 0)
	binary.BigEndian.PutUint16(out[ethLen+ipLen+6:ethLen+ipLen+8], udpChecksum(
		[4]byte{out[ethLen+12], out[ethLen+13], out[ethLen+14], out[ethLen+15]},
		[4]byte{out[ethLen+16], out[ethLen+17], out[ethLen+18], out[ethLen+19]},
		out[ethLen+ipLen:ethLen+ipLen+newUDPLen],
	))

	return out[:ethLen+newIPLen]
}

func buildTestTCPPacket(t testing.TB, syn, ack bool) []byte {
	t.Helper()

	eth := &layers.Ethernet{SrcMAC: testSrcMAC, DstMAC: testDstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.2"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 12345, DstPort: 80,
		Seq: 42, SYN: syn, ACK: ack, Window: 4096,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip4); err != nil {
		t.Fatalf("set tcp checksum layer: %v", err)
	}
	return serializeTestLayers(t, eth, ip4, tcp)
}

func serializeTestLayers(t testing.TB, items ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths: true, ComputeChecksums: true,
	}, items...); err != nil {
		t.Fatalf("serialize test packet: %v", err)
	}
	return buffer.Bytes()
}

func parseTestPacket(t testing.TB, frame []byte) gopacket.Packet {
	t.Helper()

	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		t.Fatalf("parse packet: %v", errLayer.Error())
	}
	return packet
}

func ip(raw string) net.IP {
	addr := netip.MustParseAddr(raw)
	return addr.AsSlice()
}

func sameMAC(a, b []byte) bool {
	return net.HardwareAddr(a).String() == net.HardwareAddr(b).String()
}
