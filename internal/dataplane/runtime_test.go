package dataplane

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/link"

	"sidersp/internal/rule"
)

func TestBuildSnapshotBuildsKernelIndexes(t *testing.T) {
	t.Parallel()

	set := rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID:       1001,
				Name:     "wildcard",
				Enabled:  true,
				Priority: 100,
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
			{
				ID:       1002,
				Name:     "http-80",
				Enabled:  true,
				Priority: 200,
				Match: rule.RuleMatch{
					DstPorts:    []int{80},
					SrcPrefixes: []string{"10.0.0.0/8"},
					Protocol:    "tcp",
					TCPFlags:    rule.TCPFlags{SYN: boolRulePtr(true)},
				},
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
			{
				ID:       1003,
				Name:     "http-80-specific",
				Enabled:  true,
				Priority: 300,
				Match: rule.RuleMatch{
					DstPorts:    []int{80},
					SrcPrefixes: []string{"10.1.0.0/16"},
				},
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
		},
	}

	got, err := buildSnapshot(set, Options{})
	if err != nil {
		t.Fatalf("buildSnapshot() error = %v", err)
	}

	mask80 := got.dstPortIndex[80]
	if !maskHas(mask80, 0) || !maskHas(mask80, 1) || !maskHas(mask80, 2) {
		t.Fatalf("dst port 80 mask = %+v, want all rules (wildcard + port 80 rules)", mask80.Bits)
	}
	if !maskHas(got.globalCfg.DstPortOptionalRules, 0) || maskHas(got.globalCfg.DstPortOptionalRules, 1) || maskHas(got.globalCfg.DstPortOptionalRules, 2) {
		t.Fatalf("dst port optional rules = %+v, want only wildcard rule", got.globalCfg.DstPortOptionalRules.Bits)
	}

	key16 := makeLPMKey(netip.MustParsePrefix("10.1.0.0/16"))
	mask16, ok := got.srcPrefixIndex[key16]
	if !ok {
		t.Fatal("src prefix index missing 10.1.0.0/16")
	}
	if !maskHas(mask16, 0) || !maskHas(mask16, 1) || !maskHas(mask16, 2) {
		t.Fatalf("src prefix /16 mask = %+v, want wildcard + covering prefixes", mask16.Bits)
	}

	key8 := makeLPMKey(netip.MustParsePrefix("10.0.0.0/8"))
	mask8, ok := got.srcPrefixIndex[key8]
	if !ok {
		t.Fatal("src prefix index missing 10.0.0.0/8")
	}
	if !maskHas(mask8, 0) || !maskHas(mask8, 1) || maskHas(mask8, 2) {
		t.Fatalf("src prefix /8 mask = %+v, want wildcard + /8 rule only", mask8.Bits)
	}
	if !maskHas(got.globalCfg.SrcPrefixOptionalRules, 0) || maskHas(got.globalCfg.SrcPrefixOptionalRules, 1) || maskHas(got.globalCfg.SrcPrefixOptionalRules, 2) {
		t.Fatalf("src prefix optional rules = %+v, want only wildcard rule", got.globalCfg.SrcPrefixOptionalRules.Bits)
	}

	meta := got.ruleIndex[1]
	wantMask := uint32(condProtoTCP | condSrcPrefix | condDstPort | condTCPSYN)
	if meta.RequiredMask != wantMask {
		t.Fatalf("required mask = %d, want %d", meta.RequiredMask, wantMask)
	}
	if got.globalCfg.IngressVerdict != ingressVerdictPass {
		t.Fatalf("ingress verdict = %d, want %d", got.globalCfg.IngressVerdict, ingressVerdictPass)
	}
}

func TestBuildSnapshotUsesConfiguredIngressVerdict(t *testing.T) {
	t.Parallel()

	got, err := buildSnapshot(rule.RuleSet{}, Options{IngressVerdict: "drop"})
	if err != nil {
		t.Fatalf("buildSnapshot() error = %v", err)
	}
	if got.globalCfg.IngressVerdict != ingressVerdictDrop {
		t.Fatalf("ingress verdict = %d, want %d", got.globalCfg.IngressVerdict, ingressVerdictDrop)
	}
}

func TestBuildSnapshotEncodesExtendedICMPUnreachableActions(t *testing.T) {
	t.Parallel()

	set := rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID:       2001,
				Name:     "icmp-host-unreachable",
				Enabled:  true,
				Priority: 100,
				Match:    rule.RuleMatch{Protocol: "udp"},
				Response: rule.RuleResponse{Action: "icmp_host_unreachable"},
			},
			{
				ID:       2002,
				Name:     "icmp-admin-prohibited",
				Enabled:  true,
				Priority: 200,
				Match:    rule.RuleMatch{Protocol: "udp"},
				Response: rule.RuleResponse{Action: "icmp_admin_prohibited"},
			},
		},
	}

	got, err := buildSnapshot(set, Options{})
	if err != nil {
		t.Fatalf("buildSnapshot() error = %v", err)
	}

	if got.ruleIndex[0].Action != actionICMPHostUnreachable {
		t.Fatalf("rule 0 action = %d, want %d", got.ruleIndex[0].Action, actionICMPHostUnreachable)
	}
	if got.ruleIndex[1].Action != actionICMPAdminProhibited {
		t.Fatalf("rule 1 action = %d, want %d", got.ruleIndex[1].Action, actionICMPAdminProhibited)
	}
}

func boolRulePtr(v bool) *bool {
	return &v
}

func maskHas(mask siderspMaskT, slot uint32) bool {
	group := slot / 64
	bit := slot % 64
	return mask.Bits[group]&(1<<bit) != 0
}

func TestParseAttachMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want link.XDPAttachFlags
	}{
		{name: "default", raw: "", want: link.XDPGenericMode},
		{name: "generic", raw: "generic", want: link.XDPGenericMode},
		{name: "driver", raw: "driver", want: link.XDPDriverMode},
		{name: "offload", raw: "offload", want: link.XDPOffloadMode},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseAttachMode(tc.raw)
			if err != nil {
				t.Fatalf("parseAttachMode() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("parseAttachMode() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseAttachModeRejectsUnknownValue(t *testing.T) {
	t.Parallel()

	if _, err := parseAttachMode("bad-mode"); err == nil {
		t.Fatal("parseAttachMode() error = nil, want validation error")
	}
}

func TestDecodeRuleEvent(t *testing.T) {
	t.Parallel()

	raw := make([]byte, 32)
	binary.LittleEndian.PutUint64(raw[0:8], 123)
	binary.LittleEndian.PutUint32(raw[8:12], 1001)
	binary.LittleEndian.PutUint32(raw[12:16], 9)
	binary.LittleEndian.PutUint32(raw[16:20], 0xc0a82001)
	binary.LittleEndian.PutUint32(raw[20:24], 0xc0a8209b)
	binary.LittleEndian.PutUint16(raw[24:26], actionTCPReset)
	binary.LittleEndian.PutUint16(raw[26:28], 54321)
	binary.LittleEndian.PutUint16(raw[28:30], 80)
	raw[30] = 1
	raw[31] = 6

	got, err := decodeRuleEvent(raw)
	if err != nil {
		t.Fatalf("decodeRuleEvent() error = %v", err)
	}

	if got.RuleID != 1001 || got.SPort != 54321 || got.DPort != 80 {
		t.Fatalf("decodeRuleEvent() = %+v, want decoded fields", got)
	}

	if ipv4String(got.SIP) != "192.168.32.1" {
		t.Fatalf("ipv4String(SIP) = %q, want %q", ipv4String(got.SIP), "192.168.32.1")
	}
}

func TestDiffRuleIndex(t *testing.T) {
	t.Parallel()

	prev := map[uint32]siderspRuleMeta{
		0: {RuleId: 1001, RequiredMask: condProtoTCP, Action: actionTCPReset},
		1: {RuleId: 1002, RequiredMask: condProtoUDP, Action: actionICMPPortUnreachable},
	}
	next := map[uint32]siderspRuleMeta{
		0: {RuleId: 1001, RequiredMask: condProtoTCP, Action: actionTCPReset},
		1: {RuleId: 1003, RequiredMask: condProtoTCP | condDstPort, Action: actionTCPReset},
		2: {RuleId: 1004, RequiredMask: condProtoUDP, Action: actionICMPHostUnreachable},
	}

	clears, writes := diffRuleIndex(prev, next)
	if len(clears) != 0 {
		t.Fatalf("clears = %v, want none for changed/reused slots", clears)
	}
	if len(writes) != 2 {
		t.Fatalf("writes len = %d, want 2", len(writes))
	}
	if got := writes[1].RuleId; got != 1003 {
		t.Fatalf("writes[1].RuleId = %d, want 1003", got)
	}
	if got := writes[2].RuleId; got != 1004 {
		t.Fatalf("writes[2].RuleId = %d, want 1004", got)
	}

	prev = next
	next = map[uint32]siderspRuleMeta{
		0: {RuleId: 1001, RequiredMask: condProtoTCP, Action: actionTCPReset},
	}
	clears, writes = diffRuleIndex(prev, next)
	if len(clears) != 2 || clears[0] != 1 || clears[1] != 2 {
		t.Fatalf("clears = %v, want [1 2]", clears)
	}
	if len(writes) != 0 {
		t.Fatalf("writes len = %d, want 0", len(writes))
	}
}

func TestDiffU16MaskMap(t *testing.T) {
	t.Parallel()

	prev := map[uint16]siderspMaskT{
		0:  testMask(0),
		80: testMask(1),
		81: testMask(2),
	}
	next := map[uint16]siderspMaskT{
		0:   testMask(0),
		80:  testMask(1, 3),
		443: testMask(4),
	}

	deletes, writes := diffU16MaskMap(prev, next)
	if len(deletes) != 1 || deletes[0] != 81 {
		t.Fatalf("deletes = %v, want [81]", deletes)
	}
	if len(writes) != 2 {
		t.Fatalf("writes len = %d, want 2", len(writes))
	}
	if got := writes[80]; got != testMask(1, 3) {
		t.Fatalf("writes[80] = %+v, want updated mask", got.Bits)
	}
	if got := writes[443]; got != testMask(4) {
		t.Fatalf("writes[443] = %+v, want new mask", got.Bits)
	}
}

func TestDiffPrefixMaskMap(t *testing.T) {
	t.Parallel()

	key16 := makeLPMKey(netip.MustParsePrefix("10.1.0.0/16"))
	key24 := makeLPMKey(netip.MustParsePrefix("10.1.2.0/24"))
	key32 := makeLPMKey(netip.MustParsePrefix("10.1.2.3/32"))

	prev := map[siderspIpv4LpmKey]siderspMaskT{
		key16: testMask(0),
		key24: testMask(1),
	}
	next := map[siderspIpv4LpmKey]siderspMaskT{
		key16: testMask(0, 2),
		key32: testMask(3),
	}

	deletes, writes := diffPrefixMaskMap(prev, next)
	if len(deletes) != 1 || deletes[0] != key24 {
		t.Fatalf("deletes = %v, want [%v]", deletes, key24)
	}
	if len(writes) != 2 {
		t.Fatalf("writes len = %d, want 2", len(writes))
	}
	if got := writes[key16]; got != testMask(0, 2) {
		t.Fatalf("writes[key16] = %+v, want updated mask", got.Bits)
	}
	if got := writes[key32]; got != testMask(3) {
		t.Fatalf("writes[key32] = %+v, want new mask", got.Bits)
	}
}

func TestKernelStatsFields(t *testing.T) {
	t.Parallel()

	fields := kernelStats{
		IngressPackets:                10,
		ParseOKPackets:                8,
		ParseErrorPackets:             2,
		MatchHitPackets:               4,
		MatchMissPackets:              3,
		KernelResponsePackets:         4,
		KernelResponseXDPTXPackets:    1,
		KernelResponseRedirectPackets: 2,
		KernelResponseErrorPackets:    1,
		XSKRedirectPackets:            5,
		XSKRedirectErrorPackets:       6,
		EventDroppedPackets:           7,
		DiagRuleCandidates:            8,
		DiagRedirectFailed:            9,
		DiagFibLookupFailed:           10,
		DiagXSKMetaFailed:             11,
		DiagXSKMapRedirectFailed:      12,
	}.fields()

	if got := fields["ingress_packets"]; got != uint64(10) {
		t.Fatalf("ingress_packets = %v, want %d", got, 10)
	}
	if got := fields["parse_ok_packets"]; got != uint64(8) {
		t.Fatalf("parse_ok_packets = %v, want %d", got, 8)
	}
	if got := fields["parse_error_packets"]; got != uint64(2) {
		t.Fatalf("parse_error_packets = %v, want %d", got, 2)
	}
	if got := fields["match_hit_packets"]; got != uint64(4) {
		t.Fatalf("match_hit_packets = %v, want %d", got, 4)
	}
	if got := fields["match_miss_packets"]; got != uint64(3) {
		t.Fatalf("match_miss_packets = %v, want %d", got, 3)
	}
	if got := fields["kernel_response_packets"]; got != uint64(4) {
		t.Fatalf("kernel_response_packets = %v, want %d", got, 4)
	}
	if got := fields["kernel_response_xdp_tx_packets"]; got != uint64(1) {
		t.Fatalf("kernel_response_xdp_tx_packets = %v, want %d", got, 1)
	}
	if got := fields["kernel_response_redirect_packets"]; got != uint64(2) {
		t.Fatalf("kernel_response_redirect_packets = %v, want %d", got, 2)
	}
	if got := fields["kernel_response_error_packets"]; got != uint64(1) {
		t.Fatalf("kernel_response_error_packets = %v, want %d", got, 1)
	}
	if got := fields["xsk_redirect_packets"]; got != uint64(5) {
		t.Fatalf("xsk_redirect_packets = %v, want %d", got, 5)
	}
	if got := fields["xsk_redirect_error_packets"]; got != uint64(6) {
		t.Fatalf("xsk_redirect_error_packets = %v, want %d", got, 6)
	}
	if got := fields["event_dropped_packets"]; got != uint64(7) {
		t.Fatalf("event_dropped_packets = %v, want %d", got, 7)
	}
	if got := fields["diag_rule_candidates"]; got != uint64(8) {
		t.Fatalf("diag_rule_candidates = %v, want %d", got, 8)
	}
	if got := fields["diag_redirect_failed"]; got != uint64(9) {
		t.Fatalf("diag_redirect_failed = %v, want %d", got, 9)
	}
	if got := fields["diag_fib_lookup_failed"]; got != uint64(10) {
		t.Fatalf("diag_fib_lookup_failed = %v, want %d", got, 10)
	}
	if got := fields["diag_xsk_meta_failed"]; got != uint64(11) {
		t.Fatalf("diag_xsk_meta_failed = %v, want %d", got, 11)
	}
	if got := fields["diag_xsk_map_redirect_failed"]; got != uint64(12) {
		t.Fatalf("diag_xsk_map_redirect_failed = %v, want %d", got, 12)
	}
	if len(fields) != 17 {
		t.Fatalf("len(fields) = %d, want %d", len(fields), 17)
	}
}

func testMask(slots ...uint32) siderspMaskT {
	var mask siderspMaskT
	for _, slot := range slots {
		setMaskBit(&mask, slot)
	}
	return mask
}
