package dataplane

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
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

func TestActionName(t *testing.T) {
	t.Parallel()

	if got := actionName(actionTCPReset); got != "TCP_RESET" {
		t.Fatalf("actionName(actionTCPReset) = %q, want %q", got, "TCP_RESET")
	}
	if got := actionName(actionICMPPortUnreachable); got != "ICMP_PORT_UNREACHABLE" {
		t.Fatalf("actionName(actionICMPPortUnreachable) = %q, want %q", got, "ICMP_PORT_UNREACHABLE")
	}
	if got := actionName(actionICMPHostUnreachable); got != "ICMP_HOST_UNREACHABLE" {
		t.Fatalf("actionName(actionICMPHostUnreachable) = %q, want %q", got, "ICMP_HOST_UNREACHABLE")
	}
	if got := actionName(actionICMPAdminProhibited); got != "ICMP_ADMIN_PROHIBITED" {
		t.Fatalf("actionName(actionICMPAdminProhibited) = %q, want %q", got, "ICMP_ADMIN_PROHIBITED")
	}
	if got := actionName(actionUDPEchoReply); got != "UDP_ECHO_REPLY" {
		t.Fatalf("actionName(actionUDPEchoReply) = %q, want %q", got, "UDP_ECHO_REPLY")
	}
	if got := actionName(actionDNSRefused); got != "DNS_REFUSED" {
		t.Fatalf("actionName(actionDNSRefused) = %q, want %q", got, "DNS_REFUSED")
	}
	if got := actionName(99); got != "UNKNOWN(99)" {
		t.Fatalf("actionName(99) = %q, want %q", got, "UNKNOWN(99)")
	}
}

func TestConditionNames(t *testing.T) {
	t.Parallel()

	got := conditionNames(condProtoTCP | condSrcPrefix | condDstPort | condTCPSYN)
	want := "PROTO_TCP|SRC_PREFIX|DST_PORT|TCP_SYN"
	if got != want {
		t.Fatalf("conditionNames() = %q, want %q", got, want)
	}
}

func TestFormatMaskSlots(t *testing.T) {
	t.Parallel()

	var mask siderspMaskT
	setMaskBit(&mask, 0)
	setMaskBit(&mask, 1)
	setMaskBit(&mask, 65)

	got := formatMaskSlots(mask)
	want := "[0,1,65]"
	if got != want {
		t.Fatalf("formatMaskSlots() = %q, want %q", got, want)
	}
}

func TestFormatMaskBits(t *testing.T) {
	t.Parallel()

	var mask siderspMaskT
	setMaskBit(&mask, 0)
	setMaskBit(&mask, 65)

	got := formatMaskBits(mask)
	words := make([]string, 0, len(mask.Bits))
	for _, word := range mask.Bits {
		words = append(words, fmt.Sprintf("0x%016x", word))
	}
	want := "[" + strings.Join(words, ",") + "]"
	if got != want {
		t.Fatalf("formatMaskBits() = %q, want %q", got, want)
	}
}

func TestFormatLPMKey(t *testing.T) {
	t.Parallel()

	key := makeLPMKey(netip.MustParsePrefix("10.1.0.0/16"))
	got := formatLPMKey(key)
	want := "10.1.0.0/16"
	if got != want {
		t.Fatalf("formatLPMKey() = %q, want %q", got, want)
	}
}

func TestSumPerCPUCounters(t *testing.T) {
	t.Parallel()

	got := sumPerCPUCounters([]uint64{3, 5, 7})
	if got != 15 {
		t.Fatalf("sumPerCPUCounters() = %d, want %d", got, 15)
	}
}

func TestKernelStatsFields(t *testing.T) {
	t.Parallel()

	fields := kernelStats{
		RXPackets:      10,
		ParseFailed:    2,
		RuleCandidates: 8,
		MatchedRules:   4,
		RingbufDropped: 1,
	}.fields()

	if got := fields["rx_packets"]; got != uint64(10) {
		t.Fatalf("rx_packets = %v, want %d", got, 10)
	}
	if got := fields["parse_failed"]; got != uint64(2) {
		t.Fatalf("parse_failed = %v, want %d", got, 2)
	}
	if got := fields["rule_candidates"]; got != uint64(8) {
		t.Fatalf("rule_candidates = %v, want %d", got, 8)
	}
	if got := fields["matched_rules"]; got != uint64(4) {
		t.Fatalf("matched_rules = %v, want %d", got, 4)
	}
	if got := fields["ringbuf_dropped"]; got != uint64(1) {
		t.Fatalf("ringbuf_dropped = %v, want %d", got, 1)
	}
	if got := fields["xdp_tx"]; got != uint64(0) {
		t.Fatalf("xdp_tx = %v, want %d", got, 0)
	}
	if got := fields["xsk_redirected"]; got != uint64(0) {
		t.Fatalf("xsk_redirected = %v, want %d", got, 0)
	}
	if got := fields["tx_failed"]; got != uint64(0) {
		t.Fatalf("tx_failed = %v, want %d", got, 0)
	}
	if got := fields["xsk_redirect_failed"]; got != uint64(0) {
		t.Fatalf("xsk_redirect_failed = %v, want %d", got, 0)
	}
	if got := fields["xsk_meta_failed"]; got != uint64(0) {
		t.Fatalf("xsk_meta_failed = %v, want %d", got, 0)
	}
	if got := fields["xsk_map_redirect_failed"]; got != uint64(0) {
		t.Fatalf("xsk_map_redirect_failed = %v, want %d", got, 0)
	}
	if got := fields["redirect_tx"]; got != uint64(0) {
		t.Fatalf("redirect_tx = %v, want %d", got, 0)
	}
	if got := fields["redirect_failed"]; got != uint64(0) {
		t.Fatalf("redirect_failed = %v, want %d", got, 0)
	}
	if got := fields["fib_lookup_failed"]; got != uint64(0) {
		t.Fatalf("fib_lookup_failed = %v, want %d", got, 0)
	}
	if len(fields) != 14 {
		t.Fatalf("len(fields) = %d, want %d", len(fields), 14)
	}
}
