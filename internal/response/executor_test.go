package response

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

type stubFrameTransmitter struct {
	err    error
	frames [][]byte
}

func (s *stubFrameTransmitter) SendFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

func TestResponseExecutorSendsAndRecordsResult(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1001,
		Action: ActionICMPEchoReply,
	}, buildTestICMPEchoRequest(t))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(tx.frames) != 1 {
		t.Fatalf("transmitted frames = %d, want 1", len(tx.frames))
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	result := recorded[0]
	if result.RuleID != 1001 || result.Action != "icmp_echo_reply" || result.Result != ResultSent {
		t.Fatalf("result = %+v, want sent icmp_echo_reply rule 1001", result)
	}
	if result.IfIndex != 7 || result.RXQueue != 3 {
		t.Fatalf("result location = ifindex %d queue %d, want 7/3", result.IfIndex, result.RXQueue)
	}
	if result.SIP != 0x0a000001 || result.DIP != 0x0a000002 || result.IPProto != 1 {
		t.Fatalf("result tuple = sip %x dip %x proto %d, want request tuple", result.SIP, result.DIP, result.IPProto)
	}
}

func TestResponseExecutorRecordsBuildFailure(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1002,
		Action: ActionICMPEchoReply,
	}, buildTestTCPSyn(t))
	if err == nil {
		t.Fatal("Execute() error = nil, want build error")
	}
	if len(tx.frames) != 0 {
		t.Fatalf("transmitted frames = %d, want 0", len(tx.frames))
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].Result != ResultFailed || recorded[0].Error == "" {
		t.Fatalf("result = %+v, want failed result with error", recorded[0])
	}
	if recorded[0].SPort != 12345 || recorded[0].DPort != 80 || recorded[0].IPProto != 6 {
		t.Fatalf("result tuple = sport %d dport %d proto %d, want tcp request tuple", recorded[0].SPort, recorded[0].DPort, recorded[0].IPProto)
	}
}

func TestResponseExecutorRecordsTransmitFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("tx failed")
	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{err: wantErr}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1003,
		Action: ActionICMPEchoReply,
	}, buildTestICMPEchoRequest(t))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Execute() error = %v, want %v", err, wantErr)
	}
	if len(tx.frames) != 1 {
		t.Fatalf("transmitted frames = %d, want 1", len(tx.frames))
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].Result != ResultFailed || !strings.Contains(recorded[0].Error, "transmit response frame") {
		t.Fatalf("result = %+v, want transmit failure result", recorded[0])
	}
}

func TestResponseExecutorRecordsBuildFailureForVLANRequestKeepsTuple(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1006,
		Action: ActionICMPEchoReply,
	}, buildTestVLANICMPEchoRequest(t))
	if err == nil {
		t.Fatal("Execute() error = nil, want build error")
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].SIP != 0x0a000001 || recorded[0].DIP != 0x0a000002 || recorded[0].IPProto != 1 {
		t.Fatalf("result tuple = sip %x dip %x proto %d, want vlan request tuple", recorded[0].SIP, recorded[0].DIP, recorded[0].IPProto)
	}
}

func TestResponseExecutorRejectsUnsupportedActionWithoutResult(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1004,
		Action: 99,
	}, buildTestICMPEchoRequest(t))
	if err == nil {
		t.Fatal("Execute() error = nil, want unsupported action error")
	}
	if len(tx.frames) != 0 {
		t.Fatalf("transmitted frames = %d, want 0", len(tx.frames))
	}
	if recorded := results.List(); len(recorded) != 0 {
		t.Fatalf("results = %d, want 0", len(recorded))
	}
}

func TestResponseExecutorExecutesRedirectedFrame(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.ExecuteXSK(context.Background(), buildTestXSKFrame(t, XSKMetadata{
		RuleID: 1005,
		Action: ActionICMPEchoReply,
	}, buildTestICMPEchoRequest(t)))
	if err != nil {
		t.Fatalf("ExecuteXSK() error = %v", err)
	}
	if len(tx.frames) != 1 {
		t.Fatalf("transmitted frames = %d, want 1", len(tx.frames))
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].RuleID != 1005 || recorded[0].Result != ResultSent {
		t.Fatalf("result = %+v, want sent rule 1005", recorded[0])
	}
}

func TestResponseExecutorRejectsShortRedirectedFrame(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.ExecuteXSK(context.Background(), []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("ExecuteXSK() error = nil, want short frame error")
	}
	if len(tx.frames) != 0 {
		t.Fatalf("transmitted frames = %d, want 0", len(tx.frames))
	}
	if recorded := results.List(); len(recorded) != 0 {
		t.Fatalf("results = %d, want 0", len(recorded))
	}
}

func newTestExecutor(t testing.TB, tx frameSender, results *ResultBuffer, opts BuildOptions) *ResponseExecutor {
	t.Helper()

	executor, err := NewResponseExecutor(ResponseExecutorConfig{
		IfIndex: 7,
		QueueID: 3,
		Sender: &afxdpSender{
			out:       tx,
			buildOpts: opts,
		},
		Results: results,
	})
	if err != nil {
		t.Fatalf("NewResponseExecutor() error = %v", err)
	}
	return executor
}

func buildTestXSKFrame(t testing.TB, meta XSKMetadata, payload []byte) []byte {
	t.Helper()

	frame := make([]byte, XSKMetadataSize+len(payload))
	binary.LittleEndian.PutUint32(frame[0:4], meta.RuleID)
	binary.LittleEndian.PutUint16(frame[4:6], meta.Action)
	binary.LittleEndian.PutUint16(frame[6:8], meta.Reserved)
	copy(frame[XSKMetadataSize:], payload)
	return frame
}
