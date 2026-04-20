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
				Response: rule.RuleResponse{Action: "RST"},
			},
			{
				ID:       1002,
				Name:     "http-80",
				Enabled:  true,
				Priority: 200,
				Match: rule.RuleMatch{
					DstPorts:    []int{80},
					SrcPrefixes: []string{"10.0.0.0/8"},
					Features:    []string{"TCP_SYN"},
				},
				Response: rule.RuleResponse{Action: "RST"},
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
				Response: rule.RuleResponse{Action: "RST"},
			},
		},
	}

	got, err := buildSnapshot(set)
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
	if meta.RequiredMask != condSrcPrefix|condDstPort|condTCPSYN {
		t.Fatalf("required mask = %d, want %d", meta.RequiredMask, condSrcPrefix|condDstPort|condTCPSYN)
	}
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

	raw := make([]byte, 36)
	binary.LittleEndian.PutUint64(raw[0:8], 123)
	binary.LittleEndian.PutUint32(raw[8:12], 1001)
	binary.LittleEndian.PutUint32(raw[12:16], 9)
	binary.LittleEndian.PutUint32(raw[16:20], 1)
	binary.LittleEndian.PutUint32(raw[20:24], 0xc0a82001)
	binary.LittleEndian.PutUint32(raw[24:28], 0xc0a8209b)
	binary.LittleEndian.PutUint16(raw[28:30], 54321)
	binary.LittleEndian.PutUint16(raw[30:32], 80)
	raw[32] = 0x02
	raw[33] = 6
	binary.LittleEndian.PutUint16(raw[34:36], 128)

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

	if got := actionName(1); got != "RST" {
		t.Fatalf("actionName(1) = %q, want %q", got, "RST")
	}
	if got := actionName(99); got != "UNKNOWN(99)" {
		t.Fatalf("actionName(99) = %q, want %q", got, "UNKNOWN(99)")
	}
}

func TestConditionNames(t *testing.T) {
	t.Parallel()

	got := conditionNames(condSrcPrefix | condDstPort | condTCPSYN)
	want := "SRC_PREFIX|DST_PORT|TCP_SYN"
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
	want := "[0x0000000000000001,0x0000000000000002,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000,0x0000000000000000]"
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

	if got := fields["rx"]; got != uint64(10) {
		t.Fatalf("rx = %v, want %d", got, 10)
	}
	if got := fields["parse"]; got != uint64(2) {
		t.Fatalf("parse = %v, want %d", got, 2)
	}
	if got := fields["cand"]; got != uint64(8) {
		t.Fatalf("cand = %v, want %d", got, 8)
	}
	if got := fields["match"]; got != uint64(4) {
		t.Fatalf("match = %v, want %d", got, 4)
	}
	if got := fields["drop"]; got != uint64(1) {
		t.Fatalf("drop = %v, want %d", got, 1)
	}
	if len(fields) != 5 {
		t.Fatalf("len(fields) = %d, want %d", len(fields), 5)
	}
}
