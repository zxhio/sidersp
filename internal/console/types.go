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
	XDPTX          uint64                 `json:"xdp_tx"`
	XskTX          uint64                 `json:"xsk_tx"`
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
	XDPTX          uint64 `json:"xdp_tx"`
	XskTX          uint64 `json:"xsk_tx"`
}
