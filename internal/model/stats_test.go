package model

import "testing"

func TestBuildDiagnosticStages(t *testing.T) {
	t.Parallel()

	stages := BuildDiagnosticStages(RuntimeCounters{
		Dataplane: DataplaneCounters{
			RXPackets:            100,
			ParseFailed:          2,
			RuleCandidates:       40,
			MatchedRules:         7,
			RingbufDropped:       1,
			XDPTX:                3,
			TXFailed:             5,
			XskRedirected:        4,
			XskRedirectFailed:    6,
			XskMetaFailed:        8,
			XskMapRedirectFailed: 9,
			RedirectTX:           10,
			RedirectFailed:       11,
			FibLookupFailed:      12,
		},
		Response: ResponseCounters{
			ResponseSent:     13,
			ResponseFailed:   14,
			AFXDPTX:          15,
			AFXDPTXFailed:    16,
			AFPacketTX:       17,
			AFPacketTXFailed: 18,
		},
	})

	if len(stages) != 8 {
		t.Fatalf("len(stages) = %d, want 8", len(stages))
	}
	if stages[0].Key != StatsStageIngress || stages[0].PrimaryMetricKey != StatsMetricRXPackets {
		t.Fatalf("ingress stage = %+v, want ingress rx_packets", stages[0])
	}
	if got := stages[2].Metrics[1]; got.Key != StatsMetricMatchedRules || got.Value != 7 || got.Role != MetricRoleSuccess {
		t.Fatalf("match stage metric = %+v, want matched_rules success=7", got)
	}
	responseRedirect := stages[5]
	if responseRedirect.Key != StatsStageResponseRedirect {
		t.Fatalf("response redirect stage key = %q, want %q", responseRedirect.Key, StatsStageResponseRedirect)
	}
	if got := responseRedirect.Metrics[2]; got.Key != StatsMetricXskMetaFailed || got.Value != 8 {
		t.Fatalf("response redirect meta metric = %+v, want xsk_meta_failed=8", got)
	}
	if got := responseRedirect.Metrics[3]; got.Key != StatsMetricXskMapRedirectFailed || got.Value != 9 {
		t.Fatalf("response redirect map metric = %+v, want xsk_map_redirect_failed=9", got)
	}
	responseTX := stages[7]
	if responseTX.Key != StatsStageResponseTX || responseTX.PrimaryMetricKey != StatsMetricResponseSent {
		t.Fatalf("response tx stage = %+v, want response_tx response_sent", responseTX)
	}
	if got := responseTX.Metrics[4]; got.Key != StatsMetricAFPacketTX || got.Value != 17 {
		t.Fatalf("response tx metric = %+v, want afpacket_tx=17", got)
	}
}
