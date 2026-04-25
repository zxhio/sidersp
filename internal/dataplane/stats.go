package dataplane

import (
	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
)

type kernelStats struct {
	RXPackets         uint64
	ParseFailed       uint64
	RuleCandidates    uint64
	MatchedRules      uint64
	RingbufDropped    uint64
	XDPTX             uint64
	XskTX             uint64
	TXFailed          uint64
	XskFailed         uint64
	XskMetaFailed     uint64
	XskRedirectFailed uint64
	RedirectTX        uint64
	RedirectFailed    uint64
	FibLookupFailed   uint64
}

func (s kernelStats) fields() logrus.Fields {
	return logrus.Fields{
		"rx":                s.RXPackets,
		"parse":             s.ParseFailed,
		"cand":              s.RuleCandidates,
		"match":             s.MatchedRules,
		"drop":              s.RingbufDropped,
		"xdp_tx":            s.XDPTX,
		"xsk_tx":            s.XskTX,
		"tx_fail":           s.TXFailed,
		"xsk_fail":          s.XskFailed,
		"xsk_meta_fail":     s.XskMetaFailed,
		"xsk_redirect_fail": s.XskRedirectFailed,
		"redir_tx":          s.RedirectTX,
		"redir_fail":        s.RedirectFailed,
		"fib_fail":          s.FibLookupFailed,
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
