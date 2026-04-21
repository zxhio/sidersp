package model

type DataplaneStats struct {
	RXPackets      uint64 `json:"rx_packets"`
	ParseFailed    uint64 `json:"parse_failed"`
	RuleCandidates uint64 `json:"rule_candidates"`
	MatchedRules   uint64 `json:"matched_rules"`
	RingbufDropped uint64 `json:"ringbuf_dropped"`
	XDPTX          uint64 `json:"xdp_tx"`
	XskTX          uint64 `json:"xsk_tx"`
	TXFailed       uint64 `json:"tx_failed"`
}
