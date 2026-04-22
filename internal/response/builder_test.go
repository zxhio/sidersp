package response

import (
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

func buildTestICMPEchoRequest(t *testing.T) []byte {
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

func buildTestVLANICMPEchoRequest(t *testing.T) []byte {
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

func buildTestARPRequest(t *testing.T) []byte {
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

func buildTestTCPSyn(t *testing.T) []byte {
	t.Helper()
	return buildTestTCPPacket(t, true, false)
}

func buildTestTCPSynWithPayload(t *testing.T) []byte {
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

func buildTestTCPPacket(t *testing.T, syn, ack bool) []byte {
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

func serializeTestLayers(t *testing.T, items ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths: true, ComputeChecksums: true,
	}, items...); err != nil {
		t.Fatalf("serialize test packet: %v", err)
	}
	return buffer.Bytes()
}

func parseTestPacket(t *testing.T, frame []byte) gopacket.Packet {
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
