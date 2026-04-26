package response

import (
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
)

type ResultStatus string
type TXBackend string

const (
	ResultSent    ResultStatus = "sent"
	ResultSkipped ResultStatus = "skipped"
	ResultFailed  ResultStatus = "failed"

	TXBackendAFXDP    TXBackend = "afxdp"
	TXBackendAFPacket TXBackend = "afpacket"
)

type ResponseResult struct {
	TimestampNS uint64       `json:"timestamp_ns"`
	RuleID      uint32       `json:"rule_id"`
	Action      string       `json:"action"`
	Result      ResultStatus `json:"result"`
	TXBackend   TXBackend    `json:"tx_backend"`
	IfIndex     int          `json:"ifindex"`
	RXQueue     int          `json:"rx_queue"`
	SIP         uint32       `json:"sip"`
	DIP         uint32       `json:"dip"`
	SPort       uint16       `json:"sport"`
	DPort       uint16       `json:"dport"`
	IPProto     uint8        `json:"ip_proto"`
	Error       string       `json:"error"`
}

var responseActionNames = map[uint16]string{
	ActionICMPEchoReply: "icmp_echo_reply",
	ActionARPReply:      "arp_reply",
	ActionTCPSynAck:     "tcp_syn_ack",
}

func ResponseActionName(action uint16) (string, bool) {
	name, ok := responseActionNames[action]
	return name, ok
}

type ResultBuffer struct {
	mu       sync.RWMutex
	items    []ResponseResult
	next     int
	capacity int
}

func NewResultBuffer(capacity int) (*ResultBuffer, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("create response result buffer: capacity must be positive")
	}
	return &ResultBuffer{
		items:    make([]ResponseResult, 0, capacity),
		capacity: capacity,
	}, nil
}

func (b *ResultBuffer) Record(result ResponseResult) error {
	if b == nil {
		return fmt.Errorf("record response result: nil buffer")
	}
	if err := validateResult(result); err != nil {
		return err
	}
	if result.TimestampNS == 0 {
		result.TimestampNS = uint64(time.Now().UnixNano())
	}

	b.mu.Lock()
	if len(b.items) < b.capacity {
		b.items = append(b.items, result)
	} else {
		b.items[b.next] = result
		b.next = (b.next + 1) % b.capacity
	}
	b.mu.Unlock()

	logResult(result)
	return nil
}

func (b *ResultBuffer) List() []ResponseResult {
	if b == nil {
		return nil
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]ResponseResult, 0, len(b.items))
	if len(b.items) < b.capacity {
		return append(out, b.items...)
	}

	out = append(out, b.items[b.next:]...)
	out = append(out, b.items[:b.next]...)
	return out
}

func validateResult(result ResponseResult) error {
	if result.Action == "" {
		return fmt.Errorf("record response result: action is required")
	}
	if !isResponseAction(result.Action) {
		return fmt.Errorf("record response result: unsupported action %q", result.Action)
	}
	switch result.Result {
	case ResultSent, ResultSkipped, ResultFailed:
	default:
		return fmt.Errorf("record response result: unsupported result %q", result.Result)
	}
	switch result.TXBackend {
	case TXBackendAFXDP, TXBackendAFPacket:
	default:
		return fmt.Errorf("record response result: unsupported tx_backend %q", result.TXBackend)
	}
	if result.RXQueue < 0 {
		return fmt.Errorf("record response result: rx_queue %d out of range", result.RXQueue)
	}
	return nil
}

func isResponseAction(action string) bool {
	for _, name := range responseActionNames {
		if action == name {
			return true
		}
	}
	return false
}

func logResult(result ResponseResult) {
	if result.Result != ResultFailed && !logs.App().IsLevelEnabled(logrus.DebugLevel) {
		return
	}

	fields := logrus.Fields{
		"rule_id":    result.RuleID,
		"action":     result.Action,
		"result":     result.Result,
		"tx_backend": result.TXBackend,
		"ifindex":    result.IfIndex,
		"rx_queue":   result.RXQueue,
		"sip":        result.SIP,
		"dip":        result.DIP,
		"sport":      result.SPort,
		"dport":      result.DPort,
		"ip_proto":   result.IPProto,
		"error_text": result.Error,
	}
	if result.Result == ResultFailed {
		logs.App().WithFields(fields).Warn("Fail to execute response")
		return
	}
	logs.App().WithFields(fields).Debug("Recorded response result")
}
