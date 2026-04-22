package response

import (
	"strings"
	"testing"
)

func TestResultBufferRecordsInOrder(t *testing.T) {
	t.Parallel()

	buffer := newTestResultBuffer(t, 3)
	recordTestResult(t, buffer, ResponseResult{
		TimestampNS: 1,
		RuleID:      1001,
		Action:      "icmp_echo_reply",
		Result:      ResultSent,
		RXQueue:     0,
		SIP:         0x0a000001,
		DIP:         0x0a000002,
	})
	recordTestResult(t, buffer, ResponseResult{
		TimestampNS: 2,
		RuleID:      1002,
		Action:      "arp_reply",
		Result:      ResultSkipped,
		RXQueue:     1,
	})

	results := buffer.List()
	if len(results) != 2 {
		t.Fatalf("List() len = %d, want 2", len(results))
	}
	if results[0].RuleID != 1001 || results[1].RuleID != 1002 {
		t.Fatalf("List() rule ids = %d,%d; want 1001,1002", results[0].RuleID, results[1].RuleID)
	}
	if results[0].SIP != 0x0a000001 || results[0].DIP != 0x0a000002 {
		t.Fatalf("List() ips = %d,%d; want numeric IPv4 fields", results[0].SIP, results[0].DIP)
	}
}

func TestResultBufferEvictsOldest(t *testing.T) {
	t.Parallel()

	buffer := newTestResultBuffer(t, 2)
	for i := uint32(1); i <= 4; i++ {
		recordTestResult(t, buffer, ResponseResult{
			TimestampNS: uint64(i),
			RuleID:      i,
			Action:      "tcp_syn_ack",
			Result:      ResultSent,
			RXQueue:     0,
		})
	}

	results := buffer.List()
	if len(results) != 2 {
		t.Fatalf("List() len = %d, want 2", len(results))
	}
	if results[0].RuleID != 3 || results[1].RuleID != 4 {
		t.Fatalf("List() rule ids = %d,%d; want 3,4", results[0].RuleID, results[1].RuleID)
	}
}

func TestResultBufferListReturnsCopy(t *testing.T) {
	t.Parallel()

	buffer := newTestResultBuffer(t, 2)
	recordTestResult(t, buffer, ResponseResult{
		TimestampNS: 1,
		RuleID:      1001,
		Action:      "icmp_echo_reply",
		Result:      ResultSent,
		RXQueue:     0,
	})

	results := buffer.List()
	results[0].RuleID = 9999

	next := buffer.List()
	if next[0].RuleID != 1001 {
		t.Fatalf("List() returned mutable backing storage, rule id = %d", next[0].RuleID)
	}
}

func TestResultBufferFillsTimestamp(t *testing.T) {
	t.Parallel()

	buffer := newTestResultBuffer(t, 1)
	recordTestResult(t, buffer, ResponseResult{
		RuleID:  1001,
		Action:  "icmp_echo_reply",
		Result:  ResultSent,
		RXQueue: 0,
	})

	results := buffer.List()
	if results[0].TimestampNS == 0 {
		t.Fatal("TimestampNS = 0, want generated timestamp")
	}
}

func TestResultBufferValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		create func() (*ResultBuffer, error)
		record ResponseResult
		want   string
	}{
		{
			name:   "rejects invalid capacity",
			create: func() (*ResultBuffer, error) { return NewResultBuffer(0) },
			want:   "capacity must be positive",
		},
		{
			name:   "rejects missing action",
			create: func() (*ResultBuffer, error) { return NewResultBuffer(1) },
			record: ResponseResult{Result: ResultSent},
			want:   "action is required",
		},
		{
			name:   "rejects unknown result",
			create: func() (*ResultBuffer, error) { return NewResultBuffer(1) },
			record: ResponseResult{Action: "icmp_echo_reply", Result: "unknown"},
			want:   "unsupported result",
		},
		{
			name:   "rejects unsupported action",
			create: func() (*ResultBuffer, error) { return NewResultBuffer(1) },
			record: ResponseResult{Action: "tcp_reset", Result: ResultSent},
			want:   "unsupported action",
		},
		{
			name:   "rejects negative queue",
			create: func() (*ResultBuffer, error) { return NewResultBuffer(1) },
			record: ResponseResult{Action: "icmp_echo_reply", Result: ResultSent, RXQueue: -1},
			want:   "rx_queue -1 out of range",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buffer, err := tc.create()
			if err == nil && buffer != nil {
				err = buffer.Record(tc.record)
			}
			if err == nil {
				t.Fatal("error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestResponseActionName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		action uint16
		want   string
		ok     bool
	}{
		{
			name:   "icmp echo reply",
			action: ActionICMPEchoReply,
			want:   "icmp_echo_reply",
			ok:     true,
		},
		{
			name:   "arp reply",
			action: ActionARPReply,
			want:   "arp_reply",
			ok:     true,
		},
		{
			name:   "tcp syn ack",
			action: ActionTCPSynAck,
			want:   "tcp_syn_ack",
			ok:     true,
		},
		{
			name:   "unknown",
			action: 99,
			ok:     false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := ResponseActionName(tc.action)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("ResponseActionName(%d) = %q,%v; want %q,%v", tc.action, got, ok, tc.want, tc.ok)
			}
		})
	}
}

func newTestResultBuffer(t *testing.T, capacity int) *ResultBuffer {
	t.Helper()

	buffer, err := NewResultBuffer(capacity)
	if err != nil {
		t.Fatalf("NewResultBuffer() error = %v", err)
	}
	return buffer
}

func recordTestResult(t *testing.T, buffer *ResultBuffer, result ResponseResult) {
	t.Helper()

	if err := buffer.Record(result); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
}
