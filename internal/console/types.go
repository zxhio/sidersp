package console

type RuleMatch struct {
	Protocol    string         `json:"protocol"`
	VLANs       []int          `json:"vlans"`
	SrcPrefixes []string       `json:"src_prefixes"`
	DstPrefixes []string       `json:"dst_prefixes"`
	SrcPorts    []int          `json:"src_ports"`
	DstPorts    []int          `json:"dst_ports"`
	TCPFlags    ruleTCPFlags   `json:"tcp_flags"`
	ICMP        *ruleICMPMatch `json:"icmp,omitempty"`
	ARP         *ruleARPMatch  `json:"arp,omitempty"`
}

type RuleAction struct {
	Action string                 `json:"action"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type ruleTCPFlags struct {
	SYN *bool `json:"syn,omitempty"`
	ACK *bool `json:"ack,omitempty"`
	RST *bool `json:"rst,omitempty"`
	FIN *bool `json:"fin,omitempty"`
	PSH *bool `json:"psh,omitempty"`
}

type ruleICMPMatch struct {
	Type string `json:"type"`
}

type ruleARPMatch struct {
	Operation string `json:"operation"`
}

type RuleBody struct {
	ID           int        `json:"id"`
	Name         string     `json:"name"`
	Enabled      bool       `json:"enabled"`
	Priority     int        `json:"priority"`
	MatchedCount uint64     `json:"matched_count"`
	Match        RuleMatch  `json:"match"`
	Response     RuleAction `json:"response"`
}

type StatusResponse struct {
	RulesPath   string `json:"rules_path"`
	ListenAddr  string `json:"listen_addr"`
	Interface   string `json:"interface"`
	TXInterface string `json:"tx_interface"`
	TotalRules  int    `json:"total_rules"`
	Enabled     int    `json:"enabled_rules"`
}

type StatsResponse struct {
	Overview               StatsOverviewResponse             `json:"overview"`
	Stages                 []DiagnosticStageResponse         `json:"stages"`
	RangeSeconds           int                               `json:"range_seconds"`
	CollectIntervalSeconds int                               `json:"collect_interval_seconds"`
	RetentionSeconds       int                               `json:"retention_seconds"`
	DisplayStepSeconds     int                               `json:"display_step_seconds"`
	TotalRules             *int                              `json:"total_rules,omitempty"`
	EnabledRules           *int                              `json:"enabled_rules,omitempty"`
	RXPackets              uint64                            `json:"rx_packets"`
	ParseFailed            uint64                            `json:"parse_failed"`
	RuleCandidates         uint64                            `json:"rule_candidates"`
	MatchedRules           uint64                            `json:"matched_rules"`
	RingbufDropped         *uint64                           `json:"ringbuf_dropped,omitempty"`
	XDPTX                  *uint64                           `json:"xdp_tx,omitempty"`
	XskTX                  *uint64                           `json:"xsk_tx,omitempty"`
	TXFailed               *uint64                           `json:"tx_failed,omitempty"`
	XskFailed              *uint64                           `json:"xsk_failed,omitempty"`
	XskMetaFailed          *uint64                           `json:"xsk_meta_failed,omitempty"`
	XskRedirectFailed      *uint64                           `json:"xsk_redirect_failed,omitempty"`
	RedirectTX             *uint64                           `json:"redirect_tx,omitempty"`
	RedirectFailed         *uint64                           `json:"redirect_failed,omitempty"`
	FibLookupFailed        *uint64                           `json:"fib_lookup_failed,omitempty"`
	Histories              []StatsHistoryResponse            `json:"histories"`
	StageHistories         []DiagnosticHistorySeriesResponse `json:"stage_histories"`
}

type StatsOverviewResponse struct {
	TotalRules        int    `json:"total_rules"`
	EnabledRules      int    `json:"enabled_rules"`
	RXPackets         uint64 `json:"rx_packets"`
	MatchedRules      uint64 `json:"matched_rules"`
	PrimaryIssueStage string `json:"primary_issue_stage,omitempty"`
}

type DiagnosticStageResponse struct {
	Key              string                     `json:"key"`
	Title            string                     `json:"title"`
	Summary          string                     `json:"summary"`
	PrimaryMetricKey string                     `json:"primary_metric_key"`
	Metrics          []DiagnosticMetricResponse `json:"metrics"`
}

type DiagnosticMetricResponse struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Role        string `json:"role"`
	Value       uint64 `json:"value"`
}

type StatsHistoryResponse struct {
	Name   string               `json:"name"`
	Window string               `json:"window"`
	Step   string               `json:"step"`
	Points []StatsPointResponse `json:"points"`
}

type DiagnosticHistorySeriesResponse struct {
	Name   string                           `json:"name"`
	Window string                           `json:"window"`
	Step   string                           `json:"step"`
	Stages []DiagnosticStageHistoryResponse `json:"stages"`
}

type DiagnosticStageHistoryResponse struct {
	Key              string                            `json:"key"`
	Title            string                            `json:"title"`
	Summary          string                            `json:"summary"`
	PrimaryMetricKey string                            `json:"primary_metric_key"`
	Metrics          []DiagnosticMetricHistoryResponse `json:"metrics"`
}

type DiagnosticMetricHistoryResponse struct {
	Key         string                `json:"key"`
	Label       string                `json:"label"`
	Description string                `json:"description"`
	Role        string                `json:"role"`
	Points      []MetricPointResponse `json:"points"`
}

type MetricPointResponse struct {
	Timestamp string `json:"timestamp"`
	Value     uint64 `json:"value"`
}

type StatsPointResponse struct {
	Timestamp         string  `json:"timestamp"`
	TotalRules        *int    `json:"total_rules,omitempty"`
	EnabledRules      *int    `json:"enabled_rules,omitempty"`
	RXPackets         uint64  `json:"rx_packets"`
	ParseFailed       uint64  `json:"parse_failed"`
	RuleCandidates    uint64  `json:"rule_candidates"`
	MatchedRules      uint64  `json:"matched_rules"`
	RingbufDropped    *uint64 `json:"ringbuf_dropped,omitempty"`
	XDPTX             *uint64 `json:"xdp_tx,omitempty"`
	XskTX             *uint64 `json:"xsk_tx,omitempty"`
	TXFailed          *uint64 `json:"tx_failed,omitempty"`
	XskFailed         *uint64 `json:"xsk_failed,omitempty"`
	XskMetaFailed     *uint64 `json:"xsk_meta_failed,omitempty"`
	XskRedirectFailed *uint64 `json:"xsk_redirect_failed,omitempty"`
	RedirectTX        *uint64 `json:"redirect_tx,omitempty"`
	RedirectFailed    *uint64 `json:"redirect_failed,omitempty"`
	FibLookupFailed   *uint64 `json:"fib_lookup_failed,omitempty"`
}

type LogLevelRequest struct {
	Level string `json:"level"`
}

type LogLevelResponse struct {
	Level string `json:"level"`
}
