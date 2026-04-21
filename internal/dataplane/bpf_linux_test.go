//go:build linux

package dataplane

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"sidersp/internal/rule"
)

const (
	xdpPass = 2
	xdpTX   = 3
)

// ---------------------------------------------------------------------------
// Environment gating
// ---------------------------------------------------------------------------

// requireBPFTestEnv skips the test unless SIDERSP_RUN_BPF_TESTS=1.
// BPF kernel tests need Linux + root/CAP_BPF and the XDP object compiled.
func requireBPFTestEnv(t *testing.T) {
	t.Helper()
	if os.Getenv("SIDERSP_RUN_BPF_TESTS") != "1" {
		t.Skip("set SIDERSP_RUN_BPF_TESTS=1 to run BPF kernel tests")
	}
}

// ---------------------------------------------------------------------------
// Centralized test data — independent from configs/rules.test.yaml
// ---------------------------------------------------------------------------

var testRules = []rule.Rule{
	{
		ID: 1001, Name: "rst_tcp_syn_to_ns5_port80", Enabled: true, Priority: 100,
		Match:    tcpSynMatch(rule.RuleMatch{DstPorts: []int{80}, DstPrefixes: []string{"10.0.5.2/32"}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1002, Name: "rst_tcp_syn_to_ns5_port22", Enabled: true, Priority: 100,
		Match:    tcpSynMatch(rule.RuleMatch{DstPorts: []int{22}, DstPrefixes: []string{"10.0.5.2/32"}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1010, Name: "rst_tcp_syn_from_ns3_subnet", Enabled: true, Priority: 110,
		Match:    tcpSynMatch(rule.RuleMatch{SrcPrefixes: []string{"10.0.3.0/24"}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1020, Name: "rst_tcp_syn_to_ns4_subnet", Enabled: true, Priority: 120,
		Match:    tcpSynMatch(rule.RuleMatch{DstPrefixes: []string{"10.0.4.0/24"}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1030, Name: "rst_tcp_syn_port443_any", Enabled: true, Priority: 130,
		Match:    tcpSynMatch(rule.RuleMatch{DstPorts: []int{443}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1040, Name: "rst_tcp_syn_from_high_ports", Enabled: true, Priority: 140,
		Match:    tcpSynMatch(rule.RuleMatch{SrcPorts: []int{8080, 9090}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1050, Name: "rst_ns2_to_ns5_port3306", Enabled: true, Priority: 150,
		Match:    tcpSynMatch(rule.RuleMatch{SrcPrefixes: []string{"10.0.2.0/24"}, DstPrefixes: []string{"10.0.5.0/24"}, DstPorts: []int{3306}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1070, Name: "rst_tcp_syn_multi_ports", Enabled: true, Priority: 170,
		Match:    tcpSynMatch(rule.RuleMatch{DstPorts: []int{6379, 9200, 27017}, DstPrefixes: []string{"10.0.3.0/24"}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
	{
		ID: 1060, Name: "rst_tcp_syn_to_all_test_subnets", Enabled: true, Priority: 200,
		Match:    tcpSynMatch(rule.RuleMatch{DstPrefixes: []string{"10.0.2.0/23"}}),
		Response: rule.RuleResponse{Action: "tcp_reset"},
	},
}

func tcpSynMatch(match rule.RuleMatch) rule.RuleMatch {
	match.Protocol = "tcp"
	match.TCPFlags.SYN = boolPtr(true)
	return match
}

func boolPtr(v bool) *bool {
	return &v
}

func wantXDPReturn(matched bool) uint32 {
	if matched {
		return xdpTX
	}
	return xdpPass
}

// ---------------------------------------------------------------------------
// Packet constructors
// ---------------------------------------------------------------------------

var (
	macSrc = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	macDst = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func protoToIPProto(proto string) uint8 {
	switch proto {
	case "tcp_syn", "tcp_ack", "tcp_syn_ack":
		return 6
	case "udp":
		return 17
	default:
		return 0
	}
}

func protoToTCPFlags(proto string) uint8 {
	switch proto {
	case "tcp_syn":
		return 0x02
	case "tcp_ack":
		return 0x10
	case "tcp_syn_ack":
		return 0x12
	default:
		return 0x00
	}
}

// buildEthernetPkt constructs a well-formed Ethernet+IPv4+Transport packet.
func buildEthernetPkt(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto string) []byte {
	eth := &layers.Ethernet{SrcMAC: macSrc, DstMAC: macDst, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: srcIP.AsSlice(), DstIP: dstIP.AsSlice(),
	}

	var transport gopacket.SerializableLayer
	switch proto {
	case "tcp_syn":
		ip4.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: true, Window: 65535}
		_ = tcp.SetNetworkLayerForChecksum(ip4)
		transport = tcp
	case "tcp_ack":
		ip4.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), ACK: true, Window: 65535}
		_ = tcp.SetNetworkLayerForChecksum(ip4)
		transport = tcp
	case "tcp_syn_ack":
		ip4.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: true, ACK: true, Window: 65535}
		_ = tcp.SetNetworkLayerForChecksum(ip4)
		transport = tcp
	case "udp":
		ip4.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
		_ = udp.SetNetworkLayerForChecksum(ip4)
		transport = udp
	default:
		panic("unknown proto: " + proto)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, transport); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// buildVLANTCPPkt constructs Ethernet+Dot1Q+IPv4+TCP SYN.
func buildVLANTCPPkt(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, vlan uint16) []byte {
	eth := &layers.Ethernet{SrcMAC: macSrc, DstMAC: macDst, EthernetType: layers.EthernetTypeDot1Q}
	vlanLayer := &layers.Dot1Q{VLANIdentifier: vlan, Type: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: srcIP.AsSlice(), DstIP: dstIP.AsSlice(),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), SYN: true, Window: 65535}
	_ = tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, vlanLayer, ip4, tcp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// ---- Malformed / special packet constructors ----

const (
	ethHeaderLen  = 14
	ipv4HeaderLen = 20
	arpIPv4Len    = 28

	ipv4TotalLenOffset = ethHeaderLen + 2
)

func clonePacket(pkt []byte) []byte { return append([]byte(nil), pkt...) }

func truncatePacket(pkt []byte, size int) []byte {
	out := clonePacket(pkt)
	return out[:size]
}

func withTrailingPadding(pkt []byte, padLen int) []byte {
	out := clonePacket(pkt)
	return append(out, make([]byte, padLen)...)
}

func setIPv4TotalLen(pkt []byte, totalLen uint16) []byte {
	out := clonePacket(pkt)
	binary.BigEndian.PutUint16(out[ipv4TotalLenOffset:ipv4TotalLenOffset+2], totalLen)
	return out
}

func setIPv4IHL(pkt []byte, ihl uint8) []byte {
	out := clonePacket(pkt)
	out[ethHeaderLen] = (out[ethHeaderLen] & 0xf0) | (ihl & 0x0f)
	return out
}

func buildARPPkt() []byte {
	eth := &layers.Ethernet{SrcMAC: macSrc, DstMAC: macDst, EthernetType: layers.EthernetTypeARP}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		Operation:         1,
		SourceHwAddress:   []byte(macSrc),
		SourceProtAddress: ip("192.168.1.1").AsSlice(),
		DstHwAddress:      []byte(macDst),
		DstProtAddress:    ip("192.168.2.2").AsSlice(),
	}

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func buildTruncatedARPPkt() []byte { return truncatePacket(buildARPPkt(), ethHeaderLen+8) }

func buildIPv6Pkt() []byte {
	pkt := make([]byte, ethHeaderLen+40)
	copy(pkt[0:6], macDst)
	copy(pkt[6:12], macSrc)
	pkt[12], pkt[13] = 0x86, 0xDD
	pkt[14] = 0x60
	return pkt
}

func buildUnknownEthertypePkt() []byte {
	pkt := make([]byte, 60)
	copy(pkt[0:6], macDst)
	copy(pkt[6:12], macSrc)
	pkt[12], pkt[13] = 0x09, 0x99
	return pkt
}

func buildICMPIPPkt(srcIP, dstIP netip.Addr) []byte {
	eth := &layers.Ethernet{SrcMAC: macSrc, DstMAC: macDst, EthernetType: layers.EthernetTypeIPv4}
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    srcIP.AsSlice(), DstIP: dstIP.AsSlice(),
	}
	icmp := gopacket.Payload([]byte{8, 0, 0, 0, 0, 1, 0, 1})

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, icmp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func buildTruncatedICMPPkt() []byte {
	return setIPv4TotalLen(
		truncatePacket(buildICMPIPPkt(ip("192.168.1.1"), ip("192.168.2.2")), ethHeaderLen+ipv4HeaderLen+4),
		ipv4HeaderLen+4,
	)
}

func buildTruncatedEthPkt() []byte { return make([]byte, 10) }

func buildTruncatedIPPkt() []byte {
	return truncatePacket(buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 80, "tcp_syn"), ethHeaderLen+10)
}

func buildInvalidIHLPkt() []byte {
	return setIPv4IHL(buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 80, "tcp_syn"), 3)
}

func buildIPv4OptionsPkt() []byte {
	return setIPv4IHL(buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 80, "tcp_syn"), 6)
}

func buildTruncatedTCPPkt() []byte {
	return setIPv4TotalLen(
		truncatePacket(buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 80, "tcp_syn"), ethHeaderLen+ipv4HeaderLen+10),
		ipv4HeaderLen+10,
	)
}

func buildInvalidDoffPkt() []byte {
	pkt := clonePacket(buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 80, "tcp_syn"))
	tcpDoffOffset := ethHeaderLen + ipv4HeaderLen + 12
	pkt[tcpDoffOffset] = (2 << 4) | (pkt[tcpDoffOffset] & 0x0f)
	return pkt
}

func buildTruncatedUDPPkt() []byte {
	return setIPv4TotalLen(
		truncatePacket(buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 80, "udp"), ethHeaderLen+ipv4HeaderLen+4),
		ipv4HeaderLen+4,
	)
}

// ---------------------------------------------------------------------------
// BPF test helpers
// ---------------------------------------------------------------------------

func setupBPFRuntime(t *testing.T, rules []rule.Rule) (*siderspObjects, *ringbuf.Reader) {
	t.Helper()

	require.NoError(t, rlimit.RemoveMemlock(), "remove memlock")

	var objs siderspObjects
	require.NoError(t, loadSiderspObjects(&objs, nil), "load BPF objects")

	if len(rules) > 0 {
		set := rule.RuleSet{Rules: make([]rule.Rule, len(rules))}
		copy(set.Rules, rules)

		snapshot, err := buildSnapshot(set)
		require.NoError(t, err, "build snapshot")
		writeSnapshotToMaps(t, &objs, snapshot)
	} else {
		require.NoError(t, writeGlobalConfig(objs.GlobalCfgMap, siderspGlobalCfg{}), "write empty config")
	}

	reader, err := ringbuf.NewReader(objs.EventRingbuf)
	require.NoError(t, err, "create ringbuf reader")

	return &objs, reader
}

func writeSnapshotToMaps(t *testing.T, objs *siderspObjects, snap mapSnapshot) {
	t.Helper()
	writers := []struct {
		name string
		fn   func() error
	}{
		{"rule index", func() error { return writeRuleIndex(objs.RuleIndexMap, snap.ruleIndex) }},
		{"vlan index", func() error { return writeU16MaskMap(objs.VlanIndexMap, snap.vlanIndex) }},
		{"src port index", func() error { return writeU16MaskMap(objs.SrcPortIndexMap, snap.srcPortIndex) }},
		{"dst port index", func() error { return writeU16MaskMap(objs.DstPortIndexMap, snap.dstPortIndex) }},
		{"src prefix index", func() error { return writePrefixMaskMap(objs.SrcPrefixLpmMap, snap.srcPrefixIndex) }},
		{"dst prefix index", func() error { return writePrefixMaskMap(objs.DstPrefixLpmMap, snap.dstPrefixIndex) }},
		{"global config", func() error { return writeGlobalConfig(objs.GlobalCfgMap, snap.globalCfg) }},
	}
	for _, w := range writers {
		require.NoError(t, w.fn(), "write %s", w.name)
	}
}

func readStat(t *testing.T, objs *siderspObjects, idx uint32) uint64 {
	t.Helper()
	val, err := readPerCPUCounter(objs.StatsMap, idx)
	require.NoError(t, err, "read stats[%d]", idx)
	return val
}

type eventResult struct {
	evt ruleEvent
	ok  bool
}

func readEventAsync(reader *ringbuf.Reader) <-chan eventResult {
	ch := make(chan eventResult, 1)
	go func() {
		record, err := reader.Read()
		if err != nil {
			ch <- eventResult{}
			return
		}
		evt, err := decodeRuleEvent(record.RawSample)
		if err != nil {
			ch <- eventResult{}
			return
		}
		ch <- eventResult{evt: evt, ok: true}
	}()
	return ch
}

// tryReadEvent attempts to read a ringbuf event with a short timeout.
// Returns false without failing the test if no event is available.
func tryReadEvent(t *testing.T, reader *ringbuf.Reader) (ruleEvent, bool) {
	t.Helper()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case r := <-readEventAsync(reader):
		return r.evt, r.ok
	case <-timer.C:
		return ruleEvent{}, false
	}
}

// mustReadEvent reads a ringbuf event or fails the test on timeout.
func mustReadEvent(t *testing.T, reader *ringbuf.Reader) ruleEvent {
	t.Helper()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case r := <-readEventAsync(reader):
		require.True(t, r.ok, "ringbuf read returned error")
		return r.evt
	case <-timer.C:
		t.Fatal("timed out waiting for ringbuf event (500ms)")
		return ruleEvent{}
	}
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	a := addr.As4()
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

// toRefPacket converts a test case description to a refPacket for the reference matcher.
func toRefPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto string, vlan uint16) refPacket {
	return refPacket{
		SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
		TCPFlags: protoToTCPFlags(proto), VLAN: vlan, IPProto: protoToIPProto(proto),
	}
}

// ---------------------------------------------------------------------------
// Category 1: Parser — parse correctness, safe pass, truncated packets
// ---------------------------------------------------------------------------
//
// All cases: XDP returns PASS, rx_packets incremented.
// Parse failures: parse_failed incremented, no rule match, no ringbuf event.
// Parse successes: parse_failed unchanged.

func TestBPFParserPassAndParseFailures(t *testing.T) {
	requireBPFTestEnv(t)
	objs, reader := setupBPFRuntime(t, testRules)
	defer reader.Close()
	defer objs.Close()

	tests := []struct {
		name          string
		pkt           []byte
		wantParseFail bool
	}{
		// --- Normal parse (should succeed) ---
		{"tcp_syn_ok", buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 9999, "tcp_syn"), false},
		{"tcp_ack_ok", buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 9999, "tcp_ack"), false},
		{"udp_ok", buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 9999, "udp"), false},
		{"icmp_ok", buildICMPIPPkt(ip("192.168.1.1"), ip("192.168.2.2")), false},
		{"arp_ok", buildARPPkt(), false},
		{"vlan_tcp_ok", buildVLANTCPPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 9999, 100), false},

		// --- Unsupported ethertype → PARSE_ERR_UNSUPPORTED_ETH_PROTO ---
		{"ipv6_fail", buildIPv6Pkt(), true},
		{"unknown_ethertype_fail", buildUnknownEthertypePkt(), true},

		// --- Truncated / malformed ---
		{"truncated_eth", buildTruncatedEthPkt(), true},
		{"truncated_arp", buildTruncatedARPPkt(), true},
		{"truncated_ip", buildTruncatedIPPkt(), true},
		{"truncated_icmp", buildTruncatedICMPPkt(), true},
		{"invalid_ihl", buildInvalidIHLPkt(), true},
		{"ipv4_options_unsupported", buildIPv4OptionsPkt(), true},
		{"truncated_tcp", buildTruncatedTCPPkt(), true},
		{"invalid_doff", buildInvalidDoffPkt(), true},
		{"truncated_udp", buildTruncatedUDPPkt(), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			beforeRx := readStat(t, objs, statRXPackets)
			beforePF := readStat(t, objs, statParseFailed)
			beforeMatch := readStat(t, objs, statMatchedRules)

			ret, _, err := objs.XdpSidersp.Test(tc.pkt)
			require.NoError(t, err, "prog.Test()")

			afterRx := readStat(t, objs, statRXPackets)
			afterPF := readStat(t, objs, statParseFailed)
			afterMatch := readStat(t, objs, statMatchedRules)

			if afterMatch > beforeMatch {
				require.Equal(t, uint32(xdpTX), ret, "XDP retval")
			} else {
				require.Equal(t, uint32(xdpPass), ret, "XDP retval")
			}
			require.Greater(t, afterRx, beforeRx, "rx_packets not incremented")

			if tc.wantParseFail {
				require.Greater(t, afterPF, beforePF, "parse_failed not incremented for malformed packet")
				require.LessOrEqual(t, afterMatch, beforeMatch, "parse-failed packet should not match any rule")
				// No ringbuf event for parse failures.
				_, found := tryReadEvent(t, reader)
				require.False(t, found, "unexpected ringbuf event for parse-failed packet")
			} else {
				require.Equal(t, beforePF, afterPF, "parse_failed")
				// If the packet happened to match a rule, drain the event.
				if afterMatch > beforeMatch {
					mustReadEvent(t, reader)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Category 2: Matcher — rule matching semantics (dual-implementation comparison)
// ---------------------------------------------------------------------------
//
// Each case feeds the same packet to both the reference matcher and BPF.
// Expected results are derived from refMatch(), not hardcoded.

func TestBPFRuleMatchMatrix(t *testing.T) {
	requireBPFTestEnv(t)
	objs, reader := setupBPFRuntime(t, testRules)
	defer reader.Close()
	defer objs.Close()

	tests := []struct {
		name    string
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
		proto   string
		vlan    uint16 // 0 = no VLAN tag
	}{
		// --- Single condition: dst_port only ---
		{"dst_port_443_any_ip", "172.16.0.1", "192.168.99.99", 50000, 443, "tcp_syn", 0},

		// --- Single condition: src_port only ---
		{"src_port_8080", "10.0.9.9", "10.0.8.8", 8080, 12345, "tcp_syn", 0},
		{"src_port_9090", "10.0.9.9", "10.0.8.8", 9090, 54321, "tcp_syn", 0},

		// --- Single condition: src_prefix only ---
		{"src_prefix_only", "10.0.3.50", "10.0.9.100", 45000, 9999, "tcp_syn", 0},

		// --- Single condition: dst_prefix only ---
		{"dst_prefix_only", "192.168.1.1", "10.0.4.100", 30000, 8080, "tcp_syn", 0},

		// --- Dual: dst_prefix + dst_port ---
		{"dst_prefix_port_10.0.5.2:80", "10.0.1.100", "10.0.5.2", 54321, 80, "tcp_syn", 0},
		{"dst_prefix_port_10.0.5.2:22", "10.0.1.100", "10.0.5.2", 12345, 22, "tcp_syn", 0},

		// --- Dual: dst_prefix + multi dst_ports ---
		{"dst_multi_port_6379", "10.0.1.1", "10.0.3.50", 40000, 6379, "tcp_syn", 0},
		{"dst_multi_port_9200", "10.0.1.1", "10.0.3.50", 40000, 9200, "tcp_syn", 0},
		{"dst_multi_port_27017", "10.0.1.1", "10.0.3.50", 40000, 27017, "tcp_syn", 0},

		// --- Multi: src_prefix + dst_prefix + dst_port + TCP_SYN ---
		{"multi_src_dst_port", "10.0.2.50", "10.0.5.100", 40000, 3306, "tcp_syn", 0},

		// --- Broad /23 dst_prefix ---
		{"broad_23_subnet", "10.0.9.1", "10.0.3.200", 40000, 5555, "tcp_syn", 0},

		// --- VLAN optional path: tagged packet matches rule with no VLAN condition ---
		{"vlan_tagged_match_via_optional", "10.0.1.100", "10.0.5.2", 54321, 80, "tcp_syn", 100},

		// --- No-match: wrong TCP flags ---
		{"no_match_ack", "10.0.1.100", "10.0.5.2", 54321, 80, "tcp_ack", 0},

		// --- No-match: wrong protocol ---
		{"no_match_udp", "10.0.1.100", "10.0.5.2", 54321, 80, "udp", 0},

		// --- No-match: wrong IP ---
		{"no_match_wrong_ip", "10.0.1.1", "172.16.99.99", 40000, 80, "tcp_syn", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srcIP := netip.MustParseAddr(tc.srcIP)
			dstIP := netip.MustParseAddr(tc.dstIP)

			var pkt []byte
			if tc.vlan > 0 {
				pkt = buildVLANTCPPkt(srcIP, dstIP, tc.srcPort, tc.dstPort, tc.vlan)
			} else {
				pkt = buildEthernetPkt(srcIP, dstIP, tc.srcPort, tc.dstPort, tc.proto)
			}

			refVLAN := uint16(vlanNone)
			if tc.vlan > 0 {
				refVLAN = tc.vlan
			}
			refPkt := toRefPacket(srcIP, dstIP, tc.srcPort, tc.dstPort, tc.proto, refVLAN)
			want := refMatch(testRules, refPkt)

			beforeMatch := readStat(t, objs, statMatchedRules)
			ret, _, err := objs.XdpSidersp.Test(pkt)
			require.NoError(t, err, "prog.Test()")
			afterMatch := readStat(t, objs, statMatchedRules)

			bpfMatched := afterMatch > beforeMatch
			require.Equal(t, wantXDPReturn(bpfMatched), ret, "XDP retval")
			require.Equal(t, want.Matched, bpfMatched, "BPF matched differs from reference matcher (ruleID=%d)", want.RuleID)

			if !want.Matched {
				_, found := tryReadEvent(t, reader)
				require.False(t, found, "unexpected ringbuf event for no-match case")
				return
			}

			// Verify rule ID matches the reference matcher.
			evt := mustReadEvent(t, reader)
			require.Equal(t, uint32(want.RuleID), evt.RuleID, "BPF ruleID")
		})
	}
}

// ---------------------------------------------------------------------------
// Category 3: Priority — overlapping rules, first-match-wins
// ---------------------------------------------------------------------------
//
// Each case is designed so the packet matches 2+ rules simultaneously.
// We verify (a) all listed rules actually match, (b) the highest-priority
// rule wins, (c) BPF agrees with the reference matcher.

func TestBPFPrioritySelection(t *testing.T) {
	requireBPFTestEnv(t)
	objs, reader := setupBPFRuntime(t, testRules)
	defer reader.Close()
	defer objs.Close()

	tests := []struct {
		name        string
		srcIP       string
		dstIP       string
		srcPort     uint16
		dstPort     uint16
		wantRuleID  int   // expected winner (from reference matcher)
		overlapping []int // all rule IDs that should individually match
	}{
		{
			// dst=10.0.5.2:80 → 1001 (p100), src_port=8080 → 1040 (p140)
			name: "1001_over_1040", srcIP: "10.0.1.1", dstIP: "10.0.5.2",
			srcPort: 8080, dstPort: 80, wantRuleID: 1001,
			overlapping: []int{1001, 1040},
		},
		{
			// src=10.0.3.2 → 1010 (p110), dst=10.0.3.50:6379 → 1070 (p170)
			name: "1010_over_1070", srcIP: "10.0.3.2", dstIP: "10.0.3.50",
			srcPort: 40000, dstPort: 6379, wantRuleID: 1010,
			overlapping: []int{1010, 1070},
		},
		{
			// src=10.0.3.50 → 1010 (p110), dst=10.0.2.50 → 1060 (p200, /23 covers .2.0–.3.255)
			name: "1010_over_1060", srcIP: "10.0.3.50", dstIP: "10.0.2.50",
			srcPort: 40000, dstPort: 5555, wantRuleID: 1010,
			overlapping: []int{1010, 1060},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srcIP := netip.MustParseAddr(tc.srcIP)
			dstIP := netip.MustParseAddr(tc.dstIP)
			refPkt := toRefPacket(srcIP, dstIP, tc.srcPort, tc.dstPort, "tcp_syn", vlanNone)

			// Verify overlap: every listed rule must individually match this packet.
			for _, ruleID := range tc.overlapping {
				found := false
				for _, r := range testRules {
					if r.ID == ruleID && refRuleMatches(r, refPkt) {
						found = true
						break
					}
				}
				require.True(t, found, "design error: rule %d should match this packet (overlap check)", ruleID)
			}

			want := refMatch(testRules, refPkt)
			require.Equal(t, tc.wantRuleID, want.RuleID, "reference matcher ruleID")

			pkt := buildEthernetPkt(srcIP, dstIP, tc.srcPort, tc.dstPort, "tcp_syn")
			beforeMatch := readStat(t, objs, statMatchedRules)

			ret, _, err := objs.XdpSidersp.Test(pkt)
			require.NoError(t, err, "prog.Test()")

			afterMatch := readStat(t, objs, statMatchedRules)
			require.Equal(t, uint32(xdpTX), ret, "XDP retval")
			require.Greater(t, afterMatch, beforeMatch, "packet should match at least one rule")

			evt := mustReadEvent(t, reader)
			require.Equal(t, uint32(tc.wantRuleID), evt.RuleID, "BPF ruleID")
		})
	}
}

// ---------------------------------------------------------------------------
// Category 4: Event encoding — full ringbuf event field verification
// ---------------------------------------------------------------------------
//
// Verifies every field of the 32-byte ringbuf event, including pkt_conds.

func TestBPFEventEncoding(t *testing.T) {
	requireBPFTestEnv(t)
	objs, reader := setupBPFRuntime(t, testRules)
	defer reader.Close()
	defer objs.Close()

	// Case 1: TCP SYN with known fields → verify all event fields.
	t.Run("tcp_syn_all_fields", func(t *testing.T) {
		srcIP := ip("10.0.1.100")
		dstIP := ip("10.0.5.2")
		pkt := withTrailingPadding(buildEthernetPkt(srcIP, dstIP, 54321, 80, "tcp_syn"), 18)

		ret, _, err := objs.XdpSidersp.Test(pkt)
		require.NoError(t, err, "prog.Test()")
		require.Equal(t, uint32(xdpTX), ret, "XDP retval")

		evt := mustReadEvent(t, reader)

		// rule_id: matches rule 1001 (dst 10.0.5.2/32:80, TCP_SYN)
		assert.Equal(t, uint32(1001), evt.RuleID, "rule_id")
		assert.Equal(t, actionTCPReset, evt.Action, "action")
		// sip/dip: host byte order
		assert.Equal(t, ipv4ToUint32(srcIP), evt.SIP, "sip")
		assert.Equal(t, ipv4ToUint32(dstIP), evt.DIP, "dip")
		// sport/dport: host byte order
		assert.Equal(t, uint16(54321), evt.SPort, "sport")
		assert.Equal(t, uint16(80), evt.DPort, "dport")
		// ip_proto: TCP (6)
		assert.Equal(t, uint8(6), evt.IPProto, "ip_proto")
		// pkt_conds: COND_DST_PREFIX | COND_SRC_PORT | COND_DST_PORT | COND_TCP_SYN
		//   src=10.0.1.100 → no src prefix match → no COND_SRC_PREFIX
		//   dst=10.0.5.2   → matches /32 in LPM → COND_DST_PREFIX
		//   sport=54321≠0  → COND_SRC_PORT
		//   dport=80≠0     → COND_DST_PORT
		//   SYN flag       → COND_TCP_SYN
		wantConds := uint32(condProtoTCP | condDstPrefix | condSrcPort | condDstPort | condTCPSYN)
		assert.Equal(t, wantConds, evt.PktConds, "pkt_conds")
	})

	// Case 2: Multi-condition match → verify pkt_conds includes both prefix bits.
	t.Run("multi_condition_pkt_conds", func(t *testing.T) {
		srcIP := ip("10.0.2.50")
		dstIP := ip("10.0.5.100")
		pkt := buildEthernetPkt(srcIP, dstIP, 40000, 3306, "tcp_syn")

		ret, _, err := objs.XdpSidersp.Test(pkt)
		require.NoError(t, err, "prog.Test()")
		require.Equal(t, uint32(xdpTX), ret, "XDP retval")

		evt := mustReadEvent(t, reader)

		require.Equal(t, uint32(1050), evt.RuleID, "rule_id")
		// pkt_conds: COND_SRC_PREFIX | COND_DST_PREFIX | COND_SRC_PORT | COND_DST_PORT | COND_TCP_SYN
		wantConds := uint32(condProtoTCP | condSrcPrefix | condDstPrefix | condSrcPort | condDstPort | condTCPSYN)
		assert.Equal(t, wantConds, evt.PktConds, "pkt_conds")
	})

	// Case 3: No-match → no ringbuf event, matched_rules unchanged.
	t.Run("no_match_no_event", func(t *testing.T) {
		pkt := buildEthernetPkt(ip("192.168.1.1"), ip("192.168.2.2"), 12345, 9999, "tcp_syn")

		beforeMatch := readStat(t, objs, statMatchedRules)
		ret, _, err := objs.XdpSidersp.Test(pkt)
		require.NoError(t, err, "prog.Test()")
		afterMatch := readStat(t, objs, statMatchedRules)

		require.Equal(t, uint32(xdpPass), ret, "XDP retval")
		assert.LessOrEqual(t, afterMatch, beforeMatch, "matched_rules should not increment for no-match packet")
		_, found := tryReadEvent(t, reader)
		require.False(t, found, "unexpected ringbuf event for no-match packet")
	})
}

// ---------------------------------------------------------------------------
// Category 5: Boundary — prefix boundary tests
// ---------------------------------------------------------------------------
//
// Tests prefix edge cases: first address, last address, one-before, one-after.
// Uses reference matcher as ground truth.

func TestBPFBoundaryPackets(t *testing.T) {
	requireBPFTestEnv(t)
	objs, reader := setupBPFRuntime(t, testRules)
	defer reader.Close()
	defer objs.Close()

	tests := []struct {
		name    string
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
	}{
		// --- src_prefix 10.0.3.0/24 boundary (rule 1010) ---
		{"src_24_before_10.0.2.255", "10.0.2.255", "10.0.9.1", 40000, 5555},
		{"src_24_first_10.0.3.0", "10.0.3.0", "10.0.9.1", 40000, 5555},
		{"src_24_last_10.0.3.255", "10.0.3.255", "10.0.9.1", 40000, 5555},
		{"src_24_after_10.0.4.0", "10.0.4.0", "10.0.9.1", 40000, 5555},

		// --- dst_prefix 10.0.2.0/23 boundary (rule 1060, covers 10.0.2.0–10.0.3.255) ---
		{"dst_23_before_10.0.1.255", "10.0.9.1", "10.0.1.255", 40000, 5555},
		{"dst_23_first_10.0.2.0", "10.0.9.1", "10.0.2.0", 40000, 5555},
		{"dst_23_mid_10.0.2.128", "10.0.9.1", "10.0.2.128", 40000, 5555},
		{"dst_23_boundary_10.0.3.0", "10.0.9.1", "10.0.3.0", 40000, 5555},
		{"dst_23_last_10.0.3.255", "10.0.9.1", "10.0.3.255", 40000, 5555},
		{"dst_23_after_10.0.4.0", "10.0.9.1", "10.0.4.0", 40000, 5555},

		// --- dst_prefix 10.0.5.2/32 boundary (rule 1001, port 80) ---
		{"dst_32_before_10.0.5.1:80", "10.0.1.1", "10.0.5.1", 40000, 80},
		{"dst_32_exact_10.0.5.2:80", "10.0.1.1", "10.0.5.2", 40000, 80},
		{"dst_32_after_10.0.5.3:80", "10.0.1.1", "10.0.5.3", 40000, 80},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srcIP := netip.MustParseAddr(tc.srcIP)
			dstIP := netip.MustParseAddr(tc.dstIP)
			pkt := buildEthernetPkt(srcIP, dstIP, tc.srcPort, tc.dstPort, "tcp_syn")
			refPkt := toRefPacket(srcIP, dstIP, tc.srcPort, tc.dstPort, "tcp_syn", vlanNone)
			want := refMatch(testRules, refPkt)

			beforeMatch := readStat(t, objs, statMatchedRules)
			ret, _, err := objs.XdpSidersp.Test(pkt)
			require.NoError(t, err, "prog.Test()")
			afterMatch := readStat(t, objs, statMatchedRules)

			bpfMatched := afterMatch > beforeMatch
			require.Equal(t, wantXDPReturn(bpfMatched), ret, "XDP retval")
			require.Equal(t, want.Matched, bpfMatched, "BPF matched differs from reference matcher (ruleID=%d)", want.RuleID)

			if bpfMatched {
				evt := mustReadEvent(t, reader)
				require.Equal(t, uint32(want.RuleID), evt.RuleID, "BPF ruleID")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Abnormal resource path: empty rule set
// ---------------------------------------------------------------------------

func TestBPFEmptyRules(t *testing.T) {
	requireBPFTestEnv(t)
	objs, reader := setupBPFRuntime(t, nil)
	defer reader.Close()
	defer objs.Close()

	pkt := buildEthernetPkt(ip("10.0.1.1"), ip("10.0.5.2"), 40000, 80, "tcp_syn")

	beforeMatch := readStat(t, objs, statMatchedRules)
	ret, _, err := objs.XdpSidersp.Test(pkt)
	require.NoError(t, err, "prog.Test()")
	afterMatch := readStat(t, objs, statMatchedRules)

	require.Equal(t, uint32(xdpPass), ret, "XDP retval")
	require.LessOrEqual(t, afterMatch, beforeMatch, "empty rule set should not match any packet")
	_, found := tryReadEvent(t, reader)
	require.False(t, found, "unexpected ringbuf event with empty rule set")
}

// ---------------------------------------------------------------------------
// Reference matcher self-consistency and coverage check
// ---------------------------------------------------------------------------

func TestReferenceMatcherSelfConsistent(t *testing.T) {
	// Determinism: same input → same output.
	pkt := refPacket{
		SrcIP: ip("10.0.1.100"), DstIP: ip("10.0.5.2"),
		SrcPort: 54321, DstPort: 80, TCPFlags: 0x02, VLAN: uint16(vlanNone), IPProto: 6,
	}
	r1 := refMatch(testRules, pkt)
	r2 := refMatch(testRules, pkt)
	require.Equal(t, r1, r2, "reference matcher should be deterministic")
	require.True(t, r1.Matched, "expected reference matcher hit")
	require.Equal(t, 1001, r1.RuleID, "reference matcher ruleID")

	// No-match case.
	noMatch := refPacket{
		SrcIP: ip("10.0.1.1"), DstIP: ip("172.16.99.99"),
		SrcPort: 40000, DstPort: 80, TCPFlags: 0x02, VLAN: uint16(vlanNone), IPProto: 6,
	}
	r3 := refMatch(testRules, noMatch)
	require.False(t, r3.Matched, "expected no match for unrelated IP")

	// Coverage: count how many rules are hit by the combined test packets.
	hitRules := make(map[int]bool)

	collectHits := func(srcIP, dstIP string, srcPort, dstPort uint16, proto string, vlan uint16) {
		refVLAN := vlan
		if vlan == 0 {
			refVLAN = uint16(vlanNone)
		}
		r := refMatch(testRules, toRefPacket(
			netip.MustParseAddr(srcIP), netip.MustParseAddr(dstIP),
			srcPort, dstPort, proto, refVLAN,
		))
		if r.Matched {
			hitRules[r.RuleID] = true
		}
	}

	// Matcher cases.
	for _, tc := range []struct {
		sIP    string
		dIP    string
		sP, dP uint16
		proto  string
		vlan   uint16
	}{
		{"172.16.0.1", "192.168.99.99", 50000, 443, "tcp_syn", 0},
		{"10.0.9.9", "10.0.8.8", 8080, 12345, "tcp_syn", 0},
		{"10.0.9.9", "10.0.8.8", 9090, 54321, "tcp_syn", 0},
		{"10.0.3.50", "10.0.9.100", 45000, 9999, "tcp_syn", 0},
		{"192.168.1.1", "10.0.4.100", 30000, 8080, "tcp_syn", 0},
		{"10.0.1.100", "10.0.5.2", 54321, 80, "tcp_syn", 0},
		{"10.0.1.100", "10.0.5.2", 12345, 22, "tcp_syn", 0},
		{"10.0.1.1", "10.0.3.50", 40000, 6379, "tcp_syn", 0},
		{"10.0.1.1", "10.0.3.50", 40000, 9200, "tcp_syn", 0},
		{"10.0.1.1", "10.0.3.50", 40000, 27017, "tcp_syn", 0},
		{"10.0.2.50", "10.0.5.100", 40000, 3306, "tcp_syn", 0},
		{"10.0.9.1", "10.0.3.200", 40000, 5555, "tcp_syn", 0},
		{"10.0.1.100", "10.0.5.2", 54321, 80, "tcp_syn", 100},
	} {
		collectHits(tc.sIP, tc.dIP, tc.sP, tc.dP, tc.proto, tc.vlan)
	}

	// Priority cases also contribute coverage.
	for _, tc := range []struct {
		sIP    string
		dIP    string
		sP, dP uint16
	}{
		{"10.0.1.1", "10.0.5.2", 8080, 80},
		{"10.0.3.2", "10.0.3.50", 40000, 6379},
		{"10.0.3.50", "10.0.2.50", 40000, 5555},
	} {
		collectHits(tc.sIP, tc.dIP, tc.sP, tc.dP, "tcp_syn", vlanNone)
	}

	// Boundary cases also contribute coverage.
	for _, tc := range []struct {
		sIP    string
		dIP    string
		sP, dP uint16
	}{
		{"10.0.3.0", "10.0.9.1", 40000, 5555},
		{"10.0.3.255", "10.0.9.1", 40000, 5555},
		{"10.0.9.1", "10.0.2.0", 40000, 5555},
		{"10.0.9.1", "10.0.3.0", 40000, 5555},
		{"10.0.9.1", "10.0.3.255", 40000, 5555},
	} {
		collectHits(tc.sIP, tc.dIP, tc.sP, tc.dP, "tcp_syn", vlanNone)
	}

	missing := make([]int, 0)
	for _, r := range testRules {
		if !hitRules[r.ID] {
			missing = append(missing, r.ID)
		}
	}
	require.Empty(t, missing, "rules not covered by any test packet: %v - add more test cases", missing)

	fmt.Printf("reference matcher covers all %d rules\n", len(testRules))
}
