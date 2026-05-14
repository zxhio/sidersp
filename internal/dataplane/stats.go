package dataplane

import (
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

type kernelStats struct {
	IngressPackets                uint64
	ParseOKPackets                uint64
	ParseErrorPackets             uint64
	MatchHitPackets               uint64
	MatchMissPackets              uint64
	KernelResponsePackets         uint64
	KernelResponseXDPTXPackets    uint64
	KernelResponseRedirectPackets uint64
	KernelResponseErrorPackets    uint64
	XSKRedirectPackets            uint64
	XSKRedirectErrorPackets       uint64
	EventDroppedPackets           uint64
	DiagRuleCandidates            uint64
	DiagRedirectFailed            uint64
	DiagFibLookupFailed           uint64
	DiagXSKMetaFailed             uint64
	DiagXSKMapRedirectFailed      uint64
}

func (s kernelStats) fields() logrus.Fields {
	return logrus.Fields{
		"ingress_packets":                  s.IngressPackets,
		"parse_ok_packets":                 s.ParseOKPackets,
		"parse_error_packets":              s.ParseErrorPackets,
		"match_hit_packets":                s.MatchHitPackets,
		"match_miss_packets":               s.MatchMissPackets,
		"kernel_response_packets":          s.KernelResponsePackets,
		"kernel_response_xdp_tx_packets":   s.KernelResponseXDPTXPackets,
		"kernel_response_redirect_packets": s.KernelResponseRedirectPackets,
		"kernel_response_error_packets":    s.KernelResponseErrorPackets,
		"xsk_redirect_packets":             s.XSKRedirectPackets,
		"xsk_redirect_error_packets":       s.XSKRedirectErrorPackets,
		"event_dropped_packets":            s.EventDroppedPackets,
		"diag_rule_candidates":             s.DiagRuleCandidates,
		"diag_redirect_failed":             s.DiagRedirectFailed,
		"diag_fib_lookup_failed":           s.DiagFibLookupFailed,
		"diag_xsk_meta_failed":             s.DiagXSKMetaFailed,
		"diag_xsk_map_redirect_failed":     s.DiagXSKMapRedirectFailed,
	}
}

func readPerCPUCounter(m *ebpf.Map, idx uint32) (uint64, error) {
	var values []uint64
	if err := m.Lookup(idx, &values); err != nil {
		return 0, err
	}

	return sumPerCPUCounters(values), nil
}

func sumPerCPUCounters(values []uint64) uint64 {
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}
