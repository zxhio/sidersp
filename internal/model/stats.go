package model

const (
	MetricRoleTraffic = "traffic"
	MetricRoleSuccess = "success"
	MetricRoleFailure = "failure"
)

const (
	StatsStageIngress         = "ingress"
	StatsStageParse           = "parse"
	StatsStageMatch           = "match"
	StatsStageObserve         = "observe"
	StatsStageTXSameInterface = "tx_same_interface"
	StatsStageXSKRedirect     = "xsk_redirect"
	StatsStageRedirectEgress  = "redirect_egress"
)

const (
	StatsMetricRXPackets         = "rx_packets"
	StatsMetricParseFailed       = "parse_failed"
	StatsMetricRuleCandidates    = "rule_candidates"
	StatsMetricMatchedRules      = "matched_rules"
	StatsMetricRingbufDropped    = "ringbuf_dropped"
	StatsMetricXDPTX             = "xdp_tx"
	StatsMetricXskTX             = "xsk_tx"
	StatsMetricTXFailed          = "tx_failed"
	StatsMetricXskFailed         = "xsk_failed"
	StatsMetricXskMetaFailed     = "xsk_meta_failed"
	StatsMetricXskRedirectFailed = "xsk_redirect_failed"
	StatsMetricRedirectTX        = "redirect_tx"
	StatsMetricRedirectFailed    = "redirect_failed"
	StatsMetricFibLookupFailed   = "fib_lookup_failed"
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

type DataplaneStats struct {
	RXPackets         uint64            `json:"rx_packets"`
	ParseFailed       uint64            `json:"parse_failed"`
	RuleCandidates    uint64            `json:"rule_candidates"`
	MatchedRules      uint64            `json:"matched_rules"`
	RuleMatches       map[uint32]uint64 `json:"-"`
	RingbufDropped    uint64            `json:"ringbuf_dropped"`
	XDPTX             uint64            `json:"xdp_tx"`
	XskTX             uint64            `json:"xsk_tx"`
	TXFailed          uint64            `json:"tx_failed"`
	XskFailed         uint64            `json:"xsk_failed"`
	XskMetaFailed     uint64            `json:"xsk_meta_failed"`
	XskRedirectFailed uint64            `json:"xsk_redirect_failed"`
	RedirectTX        uint64            `json:"redirect_tx"`
	RedirectFailed    uint64            `json:"redirect_failed"`
	FibLookupFailed   uint64            `json:"fib_lookup_failed"`
	Stages            []DiagnosticStage `json:"stages,omitempty"`
}

func (s DataplaneStats) Counters() DataplaneCounters {
	return DataplaneCounters{
		RXPackets:         s.RXPackets,
		ParseFailed:       s.ParseFailed,
		RuleCandidates:    s.RuleCandidates,
		MatchedRules:      s.MatchedRules,
		RingbufDropped:    s.RingbufDropped,
		XDPTX:             s.XDPTX,
		XskTX:             s.XskTX,
		TXFailed:          s.TXFailed,
		XskFailed:         s.XskFailed,
		XskMetaFailed:     s.XskMetaFailed,
		XskRedirectFailed: s.XskRedirectFailed,
		RedirectTX:        s.RedirectTX,
		RedirectFailed:    s.RedirectFailed,
		FibLookupFailed:   s.FibLookupFailed,
	}
}

func BuildDiagnosticStages(counters DataplaneCounters) []DiagnosticStage {
	return []DiagnosticStage{
		{
			Key:              StatsStageIngress,
			PrimaryMetricKey: StatsMetricRXPackets,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRXPackets, Role: MetricRoleTraffic, Value: counters.RXPackets},
			},
		},
		{
			Key:              StatsStageParse,
			PrimaryMetricKey: StatsMetricParseFailed,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricParseFailed, Role: MetricRoleFailure, Value: counters.ParseFailed},
			},
		},
		{
			Key:              StatsStageMatch,
			PrimaryMetricKey: StatsMetricMatchedRules,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRuleCandidates, Role: MetricRoleTraffic, Value: counters.RuleCandidates},
				{Key: StatsMetricMatchedRules, Role: MetricRoleSuccess, Value: counters.MatchedRules},
			},
		},
		{
			Key:              StatsStageObserve,
			PrimaryMetricKey: StatsMetricRingbufDropped,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRingbufDropped, Role: MetricRoleFailure, Value: counters.RingbufDropped},
			},
		},
		{
			Key:              StatsStageTXSameInterface,
			PrimaryMetricKey: StatsMetricXDPTX,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricXDPTX, Role: MetricRoleSuccess, Value: counters.XDPTX},
				{Key: StatsMetricTXFailed, Role: MetricRoleFailure, Value: counters.TXFailed},
			},
		},
		{
			Key:              StatsStageXSKRedirect,
			PrimaryMetricKey: StatsMetricXskTX,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricXskTX, Role: MetricRoleSuccess, Value: counters.XskTX},
				{Key: StatsMetricXskFailed, Role: MetricRoleFailure, Value: counters.XskFailed},
				{Key: StatsMetricXskMetaFailed, Role: MetricRoleFailure, Value: counters.XskMetaFailed},
				{Key: StatsMetricXskRedirectFailed, Role: MetricRoleFailure, Value: counters.XskRedirectFailed},
			},
		},
		{
			Key:              StatsStageRedirectEgress,
			PrimaryMetricKey: StatsMetricRedirectTX,
			Metrics: []DiagnosticMetric{
				{Key: StatsMetricRedirectTX, Role: MetricRoleSuccess, Value: counters.RedirectTX},
				{Key: StatsMetricRedirectFailed, Role: MetricRoleFailure, Value: counters.RedirectFailed},
				{Key: StatsMetricFibLookupFailed, Role: MetricRoleFailure, Value: counters.FibLookupFailed},
			},
		},
	}
}
