package controlplane

import (
	"net/netip"
	"strings"
	"time"

	"sidersp/internal/model"
	"sidersp/internal/response"
)

type EventSource interface {
	Events() []model.EventRecord
}

type ResponseResultSource interface {
	Results() []response.ResponseResult
}

type EventQuery struct {
	Page     int
	PageSize int
	RuleID   int
	Action   string
	Verdict  string
}

type ResponseResultQuery struct {
	Page      int
	PageSize  int
	RuleID    int
	Action    string
	Result    string
	TXBackend string
}

type EventRecord struct {
	Timestamp    time.Time `json:"-"`
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

type ResponseResultRecord struct {
	Timestamp   time.Time `json:"-"`
	TimestampNS uint64    `json:"timestamp_ns"`
	RuleID      uint32    `json:"rule_id"`
	Action      string    `json:"action"`
	Result      string    `json:"result"`
	TXBackend   string    `json:"tx_backend"`
	IfIndex     int       `json:"ifindex"`
	RXQueue     int       `json:"rx_queue"`
	SIP         string    `json:"sip"`
	DIP         string    `json:"dip"`
	SPort       uint16    `json:"sport"`
	DPort       uint16    `json:"dport"`
	IPProto     uint8     `json:"ip_proto"`
	Error       string    `json:"error"`
}

type EventPage struct {
	Items    []EventRecord
	Total    int
	Page     int
	PageSize int
}

type ResponseResultPage struct {
	Items    []ResponseResultRecord
	Total    int
	Page     int
	PageSize int
}

func (r *Runtime) ListEvents(query EventQuery) (EventPage, error) {
	items := make([]EventRecord, 0)
	if r.eventSource != nil {
		source := r.eventSource.Events()
		items = make([]EventRecord, 0, len(source))
		for idx := len(source) - 1; idx >= 0; idx-- {
			item := source[idx]
			if !eventMatchesQuery(item, query) {
				continue
			}
			items = append(items, EventRecord{
				Timestamp:    item.ObservedAt,
				TimestampNS:  item.TimestampNS,
				RuleID:       item.RuleID,
				PktConds:     item.PktConds,
				PktCondNames: item.PktCondNames,
				Action:       item.Action,
				Verdict:      item.Verdict,
				SIP:          item.SIP,
				DIP:          item.DIP,
				SPort:        item.SPort,
				DPort:        item.DPort,
				IPProto:      item.IPProto,
			})
		}
	}

	return EventPage{
		Items:    paginateEventRecords(items, query.Page, query.PageSize),
		Total:    len(items),
		Page:     query.Page,
		PageSize: query.PageSize,
	}, nil
}

func (r *Runtime) ListResponseResults(query ResponseResultQuery) (ResponseResultPage, error) {
	items := make([]ResponseResultRecord, 0)
	if r.resultSource != nil {
		source := r.resultSource.Results()
		items = make([]ResponseResultRecord, 0, len(source))
		for idx := len(source) - 1; idx >= 0; idx-- {
			item := source[idx]
			if !responseResultMatchesQuery(item, query) {
				continue
			}
			items = append(items, ResponseResultRecord{
				Timestamp:   time.Unix(0, int64(item.TimestampNS)).UTC(),
				TimestampNS: item.TimestampNS,
				RuleID:      item.RuleID,
				Action:      item.Action,
				Result:      string(item.Result),
				TXBackend:   string(item.TXBackend),
				IfIndex:     item.IfIndex,
				RXQueue:     item.RXQueue,
				SIP:         ipv4String(item.SIP),
				DIP:         ipv4String(item.DIP),
				SPort:       item.SPort,
				DPort:       item.DPort,
				IPProto:     item.IPProto,
				Error:       item.Error,
			})
		}
	}

	return ResponseResultPage{
		Items:    paginateResponseResultRecords(items, query.Page, query.PageSize),
		Total:    len(items),
		Page:     query.Page,
		PageSize: query.PageSize,
	}, nil
}

func eventMatchesQuery(item model.EventRecord, query EventQuery) bool {
	if query.RuleID > 0 && item.RuleID != uint32(query.RuleID) {
		return false
	}
	if action := strings.ToLower(strings.TrimSpace(query.Action)); action != "" && item.Action != action {
		return false
	}
	if verdict := strings.ToLower(strings.TrimSpace(query.Verdict)); verdict != "" && item.Verdict != verdict {
		return false
	}
	return true
}

func responseResultMatchesQuery(item response.ResponseResult, query ResponseResultQuery) bool {
	if query.RuleID > 0 && item.RuleID != uint32(query.RuleID) {
		return false
	}
	if action := strings.ToLower(strings.TrimSpace(query.Action)); action != "" && item.Action != action {
		return false
	}
	if result := strings.ToLower(strings.TrimSpace(query.Result)); result != "" && string(item.Result) != result {
		return false
	}
	if backend := strings.ToLower(strings.TrimSpace(query.TXBackend)); backend != "" && string(item.TXBackend) != backend {
		return false
	}
	return true
}

func paginateEventRecords(items []EventRecord, page int, pageSize int) []EventRecord {
	start := (page - 1) * pageSize
	if start > len(items) {
		start = len(items)
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return append([]EventRecord(nil), items[start:end]...)
}

func paginateResponseResultRecords(items []ResponseResultRecord, page int, pageSize int) []ResponseResultRecord {
	start := (page - 1) * pageSize
	if start > len(items) {
		start = len(items)
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return append([]ResponseResultRecord(nil), items[start:end]...)
}

func ipv4String(v uint32) string {
	addr := [4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
	return netip.AddrFrom4(addr).String()
}
