package model

import "testing"

func TestBuildDiagnosticStages(t *testing.T) {
	t.Parallel()

	stages := BuildDiagnosticStages(DataplaneCounters{
		RXPackets:         100,
		ParseFailed:       2,
		RuleCandidates:    40,
		MatchedRules:      7,
		RingbufDropped:    1,
		XDPTX:             3,
		XskTX:             4,
		TXFailed:          5,
		XskFailed:         6,
		XskMetaFailed:     8,
		XskRedirectFailed: 9,
		RedirectTX:        10,
		RedirectFailed:    11,
		FibLookupFailed:   12,
	})

	if len(stages) != 7 {
		t.Fatalf("len(stages) = %d, want 7", len(stages))
	}
	if stages[0].Key != StatsStageIngress || stages[0].PrimaryMetricKey != StatsMetricRXPackets {
		t.Fatalf("ingress stage = %+v, want ingress rx_packets", stages[0])
	}
	if got := stages[2].Metrics[1]; got.Key != StatsMetricMatchedRules || got.Value != 7 || got.Role != MetricRoleSuccess {
		t.Fatalf("match stage metric = %+v, want matched_rules success=7", got)
	}
	xsk := stages[5]
	if xsk.Key != StatsStageXSKRedirect {
		t.Fatalf("xsk stage key = %q, want %q", xsk.Key, StatsStageXSKRedirect)
	}
	if got := xsk.Metrics[2]; got.Key != StatsMetricXskMetaFailed || got.Value != 8 {
		t.Fatalf("xsk meta metric = %+v, want xsk_meta_failed=8", got)
	}
	if got := xsk.Metrics[3]; got.Key != StatsMetricXskRedirectFailed || got.Value != 9 {
		t.Fatalf("xsk redirect metric = %+v, want xsk_redirect_failed=9", got)
	}
}
