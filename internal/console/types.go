package console

type RuleMatch struct {
	VLANs       []int    `json:"vlans"`
	SrcPrefixes []string `json:"src_prefixes"`
	DstPrefixes []string `json:"dst_prefixes"`
	SrcPorts    []int    `json:"src_ports"`
	DstPorts    []int    `json:"dst_ports"`
	Features    []string `json:"features"`
}

type RuleAction struct {
	Action string `json:"action"`
}

type RuleBody struct {
	ID       int        `json:"id"`
	Name     string     `json:"name"`
	Enabled  bool       `json:"enabled"`
	Priority int        `json:"priority"`
	Match    RuleMatch  `json:"match"`
	Response RuleAction `json:"response"`
}

type StatusResponse struct {
	RulesPath  string `json:"rules_path"`
	ListenAddr string `json:"listen_addr"`
	Interface  string `json:"interface"`
	TotalRules int    `json:"total_rules"`
	Enabled    int    `json:"enabled_rules"`
}

type StatsResponse struct {
	TotalRules     int                    `json:"total_rules"`
	EnabledRules   int                    `json:"enabled_rules"`
	RXPackets      uint64                 `json:"rx_packets"`
	ParseFailed    uint64                 `json:"parse_failed"`
	RuleCandidates uint64                 `json:"rule_candidates"`
	MatchedRules   uint64                 `json:"matched_rules"`
	RingbufDropped uint64                 `json:"ringbuf_dropped"`
	Histories      []StatsHistoryResponse `json:"histories"`
}

type StatsHistoryResponse struct {
	Name   string               `json:"name"`
	Window string               `json:"window"`
	Step   string               `json:"step"`
	Points []StatsPointResponse `json:"points"`
}

type StatsPointResponse struct {
	Timestamp      string `json:"timestamp"`
	TotalRules     int    `json:"total_rules"`
	EnabledRules   int    `json:"enabled_rules"`
	RXPackets      uint64 `json:"rx_packets"`
	ParseFailed    uint64 `json:"parse_failed"`
	RuleCandidates uint64 `json:"rule_candidates"`
	MatchedRules   uint64 `json:"matched_rules"`
	RingbufDropped uint64 `json:"ringbuf_dropped"`
}
