package model

import "time"

type EventRecord struct {
	ObservedAt   time.Time `json:"-"`
	TimestampNS  uint64    `json:"timestamp_ns"`
	RuleID       uint32    `json:"rule_id"`
	PktConds     uint32    `json:"pkt_conds"`
	PktCondNames string    `json:"pkt_cond_names"`
	Action       string    `json:"action"`
	Verdict      string    `json:"verdict"`
	SIP          string    `json:"sip"`
	DIP          string    `json:"dip"`
	SPort        uint16    `json:"sport"`
	DPort        uint16    `json:"dport"`
	IPProto      uint8     `json:"ip_proto"`
}
