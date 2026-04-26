package model

const (
	MetricRoleTraffic = "traffic"
	MetricRoleSuccess = "success"
	MetricRoleFailure = "failure"
)

const (
	StatsStageIngress          = "ingress"
	StatsStageParse            = "parse"
	StatsStageMatch            = "match"
	StatsStageObserve          = "observe"
	StatsStageTXSameInterface  = "tx_same_interface"
	StatsStageResponseRedirect = "response_redirect"
	StatsStageRedirectEgress   = "redirect_egress"
	StatsStageResponseTX       = "response_tx"
)

const (
	StatsMetricRXPackets            = "rx_packets"
	StatsMetricParseFailed          = "parse_failed"
	StatsMetricRuleCandidates       = "rule_candidates"
	StatsMetricMatchedRules         = "matched_rules"
	StatsMetricRingbufDropped       = "ringbuf_dropped"
	StatsMetricXDPTX                = "xdp_tx"
	StatsMetricTXFailed             = "tx_failed"
	StatsMetricXskRedirected        = "xsk_redirected"
	StatsMetricXskRedirectFailed    = "xsk_redirect_failed"
	StatsMetricXskMetaFailed        = "xsk_meta_failed"
	StatsMetricXskMapRedirectFailed = "xsk_map_redirect_failed"
	StatsMetricRedirectTX           = "redirect_tx"
	StatsMetricRedirectFailed       = "redirect_failed"
	StatsMetricFibLookupFailed      = "fib_lookup_failed"
	StatsMetricResponseSent         = "response_sent"
	StatsMetricResponseFailed       = "response_failed"
	StatsMetricAFXDPTX              = "afxdp_tx"
	StatsMetricAFXDPTXFailed        = "afxdp_tx_failed"
	StatsMetricAFPacketTX           = "afpacket_tx"
	StatsMetricAFPacketTXFailed     = "afpacket_tx_failed"
)

type DiagnosticMetric struct {
	Key   string `json:"key"`
	Role  string `json:"role"`
	Value uint64 `json:"value"`
}

type DiagnosticStage struct {
	Key              string             `json:"key"`
	PrimaryMetricKey string             `json:"primary_metric_key"`
	Metrics          []DiagnosticMetric `json:"metrics"`
}

type DataplaneCounters struct {
	RXPackets            uint64
	ParseFailed          uint64
	RuleCandidates       uint64
	MatchedRules         uint64
	RingbufDropped       uint64
	XDPTX                uint64
	TXFailed             uint64
	XskRedirected        uint64
	XskRedirectFailed    uint64
	XskMetaFailed        uint64
	XskMapRedirectFailed uint64
	RedirectTX           uint64
	RedirectFailed       uint64
	FibLookupFailed      uint64
}

type DataplaneStats struct {
	RXPackets            uint64            `json:"rx_packets"`
	ParseFailed          uint64            `json:"parse_failed"`
	RuleCandidates       uint64            `json:"rule_candidates"`
	MatchedRules         uint64            `json:"matched_rules"`
	RuleMatches          map[uint32]uint64 `json:"-"`
	RingbufDropped       uint64            `json:"ringbuf_dropped"`
	XDPTX                uint64            `json:"xdp_tx"`
	TXFailed             uint64            `json:"tx_failed"`
	XskRedirected        uint64            `json:"xsk_redirected"`
	XskRedirectFailed    uint64            `json:"xsk_redirect_failed"`
	XskMetaFailed        uint64            `json:"xsk_meta_failed"`
	XskMapRedirectFailed uint64            `json:"xsk_map_redirect_failed"`
	RedirectTX           uint64            `json:"redirect_tx"`
	RedirectFailed       uint64            `json:"redirect_failed"`
	FibLookupFailed      uint64            `json:"fib_lookup_failed"`
}

func (s DataplaneStats) Counters() DataplaneCounters {
	return DataplaneCounters{
		RXPackets:            s.RXPackets,
		ParseFailed:          s.ParseFailed,
		RuleCandidates:       s.RuleCandidates,
		MatchedRules:         s.MatchedRules,
		RingbufDropped:       s.RingbufDropped,
		XDPTX:                s.XDPTX,
		TXFailed:             s.TXFailed,
		XskRedirected:        s.XskRedirected,
		XskRedirectFailed:    s.XskRedirectFailed,
		XskMetaFailed:        s.XskMetaFailed,
		XskMapRedirectFailed: s.XskMapRedirectFailed,
		RedirectTX:           s.RedirectTX,
		RedirectFailed:       s.RedirectFailed,
		FibLookupFailed:      s.FibLookupFailed,
	}
}

type ResponseCounters struct {
	ResponseSent     uint64
	ResponseFailed   uint64
	AFXDPTX          uint64
	AFXDPTXFailed    uint64
	AFPacketTX       uint64
	AFPacketTXFailed uint64
}

type ResponseStats struct {
	ResponseSent     uint64 `json:"response_sent"`
	ResponseFailed   uint64 `json:"response_failed"`
	AFXDPTX          uint64 `json:"afxdp_tx"`
	AFXDPTXFailed    uint64 `json:"afxdp_tx_failed"`
	AFPacketTX       uint64 `json:"afpacket_tx"`
	AFPacketTXFailed uint64 `json:"afpacket_tx_failed"`
}

func (s ResponseStats) Counters() ResponseCounters {
	return ResponseCounters{
		ResponseSent:     s.ResponseSent,
		ResponseFailed:   s.ResponseFailed,
		AFXDPTX:          s.AFXDPTX,
		AFXDPTXFailed:    s.AFXDPTXFailed,
		AFPacketTX:       s.AFPacketTX,
		AFPacketTXFailed: s.AFPacketTXFailed,
	}
}

type RuntimeStats struct {
	Dataplane DataplaneStats `json:"dataplane"`
	Response  ResponseStats  `json:"response"`
}

type RuntimeCounters struct {
	Dataplane DataplaneCounters
	Response  ResponseCounters
}

func (s RuntimeStats) Counters() RuntimeCounters {
	return RuntimeCounters{
		Dataplane: s.Dataplane.Counters(),
		Response:  s.Response.Counters(),
	}
}

func BuildDiagnosticStages(counters RuntimeCounters) []DiagnosticStage {
	return []DiagnosticStage{
		{
			Key:              StatsStageIngress,
			PrimaryMetricKey: StatsMetricRXPackets,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRXPackets, Role: MetricRoleTraffic, Value: counters.Dataplane.RXPackets},
			},
		},
		{
			Key:              StatsStageParse,
			PrimaryMetricKey: StatsMetricParseFailed,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricParseFailed, Role: MetricRoleFailure, Value: counters.Dataplane.ParseFailed},
			},
		},
		{
			Key:              StatsStageMatch,
			PrimaryMetricKey: StatsMetricMatchedRules,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRuleCandidates, Role: MetricRoleTraffic, Value: counters.Dataplane.RuleCandidates},
				{Key: StatsMetricMatchedRules, Role: MetricRoleSuccess, Value: counters.Dataplane.MatchedRules},
			},
		},
		{
			Key:              StatsStageObserve,
			PrimaryMetricKey: StatsMetricRingbufDropped,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRingbufDropped, Role: MetricRoleFailure, Value: counters.Dataplane.RingbufDropped},
			},
		},
		{
			Key:              StatsStageTXSameInterface,
			PrimaryMetricKey: StatsMetricXDPTX,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricXDPTX, Role: MetricRoleSuccess, Value: counters.Dataplane.XDPTX},
				{Key: StatsMetricTXFailed, Role: MetricRoleFailure, Value: counters.Dataplane.TXFailed},
			},
		},
		{
			Key:              StatsStageResponseRedirect,
			PrimaryMetricKey: StatsMetricXskRedirected,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricXskRedirected, Role: MetricRoleSuccess, Value: counters.Dataplane.XskRedirected},
				{Key: StatsMetricXskRedirectFailed, Role: MetricRoleFailure, Value: counters.Dataplane.XskRedirectFailed},
				{Key: StatsMetricXskMetaFailed, Role: MetricRoleFailure, Value: counters.Dataplane.XskMetaFailed},
				{Key: StatsMetricXskMapRedirectFailed, Role: MetricRoleFailure, Value: counters.Dataplane.XskMapRedirectFailed},
			},
		},
		{
			Key:              StatsStageRedirectEgress,
			PrimaryMetricKey: StatsMetricRedirectTX,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRedirectTX, Role: MetricRoleSuccess, Value: counters.Dataplane.RedirectTX},
				{Key: StatsMetricRedirectFailed, Role: MetricRoleFailure, Value: counters.Dataplane.RedirectFailed},
				{Key: StatsMetricFibLookupFailed, Role: MetricRoleFailure, Value: counters.Dataplane.FibLookupFailed},
			},
		},
		{
			Key:              StatsStageResponseTX,
			PrimaryMetricKey: StatsMetricResponseSent,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricResponseSent, Role: MetricRoleSuccess, Value: counters.Response.ResponseSent},
				{Key: StatsMetricResponseFailed, Role: MetricRoleFailure, Value: counters.Response.ResponseFailed},
				{Key: StatsMetricAFXDPTX, Role: MetricRoleSuccess, Value: counters.Response.AFXDPTX},
				{Key: StatsMetricAFXDPTXFailed, Role: MetricRoleFailure, Value: counters.Response.AFXDPTXFailed},
				{Key: StatsMetricAFPacketTX, Role: MetricRoleSuccess, Value: counters.Response.AFPacketTX},
				{Key: StatsMetricAFPacketTXFailed, Role: MetricRoleFailure, Value: counters.Response.AFPacketTXFailed},
			},
		},
	}
}
