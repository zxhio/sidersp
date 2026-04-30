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
	if result.TXBackend != TXBackendAFXDP {
		t.Fatalf("result backend = %q, want %q", result.TXBackend, TXBackendAFXDP)
	}
	if result.IfIndex != 7 || result.RXQueue != 3 {
		t.Fatalf("result location = ifindex %d queue %d, want 7/3", result.IfIndex, result.RXQueue)
	}
	if result.SIP != 0x0a000001 || result.DIP != 0x0a000002 || result.IPProto != 1 {
		t.Fatalf("result tuple = sip %x dip %x proto %d, want request tuple", result.SIP, result.DIP, result.IPProto)
	}
	if got := executor.stats.snapshot(); got.ResponseSent != 1 || got.AFXDPTX != 1 || got.ResponseFailed != 0 {
		t.Fatalf("stats = %+v, want response_sent=1 afxdp_tx=1 response_failed=0", got)
	}
}

func TestResponseExecutorSendsAndRecordsUDPEchoResult(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 2001,
		Action: ActionUDPEchoReply,
	}, buildTestUDPDatagram(t, 12345, 7, []byte("echo-me")))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].Action != "udp_echo_reply" || recorded[0].Result != ResultSent {
		t.Fatalf("result = %+v, want sent udp_echo_reply", recorded[0])
	}
	if recorded[0].SPort != 12345 || recorded[0].DPort != 7 || recorded[0].IPProto != 17 {
		t.Fatalf("result tuple = sport %d dport %d proto %d, want 12345/7/17", recorded[0].SPort, recorded[0].DPort, recorded[0].IPProto)
	}
}

func TestResponseExecutorRecordsDNSBuildFailure(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, BuildOptions{})

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 2002,
		Action: ActionDNSRefused,
	}, buildTestUDPDatagram(t, 12345, 53, []byte("short")))
	if err == nil {
		t.Fatal("Execute() error = nil, want build error")
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].Action != "dns_refused" || recorded[0].Result != ResultFailed || recorded[0].Error == "" {
		t.Fatalf("result = %+v, want failed dns_refused result", recorded[0])
	}
}

func TestResponseExecutorSendsAndRecordsDNSSinkholeResult(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	executor := newTestExecutor(t, tx, results, testDNSSinkholeBuildOptions(t, 2003, "192.0.2.10"))

	err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 2003,
		Action: ActionDNSSinkhole,
	}, buildTestDNSQuery(t, "example.org"))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	recorded := results.List()
	if len(recorded) != 1 {
		t.Fatalf("results = %d, want 1", len(recorded))
	}
	if recorded[0].Action != "dns_sinkhole" || recorded[0].Result != ResultSent {
		t.Fatalf("result = %+v, want sent dns_sinkhole result", recorded[0])
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
	if recorded[0].TXBackend != TXBackendAFXDP {
		t.Fatalf("result backend = %q, want %q", recorded[0].TXBackend, TXBackendAFXDP)
	}
	if recorded[0].SPort != 12345 || recorded[0].DPort != 80 || recorded[0].IPProto != 6 {
		t.Fatalf("result tuple = sport %d dport %d proto %d, want tcp request tuple", recorded[0].SPort, recorded[0].DPort, recorded[0].IPProto)
	}
	if got := executor.stats.snapshot(); got.ResponseFailed != 1 || got.AFXDPTXFailed != 1 || got.ResponseSent != 0 {
		t.Fatalf("stats = %+v, want response_failed=1 afxdp_tx_failed=1 response_sent=0", got)
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
	if recorded[0].TXBackend != TXBackendAFXDP {
		t.Fatalf("result backend = %q, want %q", recorded[0].TXBackend, TXBackendAFXDP)
	}
	if got := executor.stats.snapshot(); got.ResponseFailed != 1 || got.AFXDPTXFailed != 1 || got.AFXDPTX != 0 {
		t.Fatalf("stats = %+v, want response_failed=1 afxdp_tx_failed=1 afxdp_tx=0", got)
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
	if recorded[0].SIP != 0 || recorded[0].DIP != 0 || recorded[0].IPProto != 0 {
		t.Fatalf("result tuple = sip %x dip %x proto %d, want empty tuple for vlan decode failure", recorded[0].SIP, recorded[0].DIP, recorded[0].IPProto)
	}
	if got := executor.stats.snapshot(); got.ResponseFailed != 1 || got.AFXDPTXFailed != 1 {
		t.Fatalf("stats = %+v, want response_failed=1 afxdp_tx_failed=1", got)
	}
}

func TestResponseExecutorTracksAFPacketBackend(t *testing.T) {
	t.Parallel()

	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{}
	stats := newStatsCounters()
	executor, err := NewResponseExecutor(ResponseExecutorConfig{
		IfIndex: 7,
		QueueID: 3,
		Sender: &afpacketSender{
			out: tx,
			buildOpts: BuildOptions{
				HardwareAddr: testHWAddr,
			},
		},
		Results: results,
		Stats:   stats,
	})
	if err != nil {
		t.Fatalf("NewResponseExecutor() error = %v", err)
	}

	if err := executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1007,
		Action: ActionARPReply,
	}, buildTestARPRequest(t)); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	recorded := results.List()
	if len(recorded) != 1 || recorded[0].TXBackend != TXBackendAFPacket {
		t.Fatalf("results = %+v, want one afpacket result", recorded)
	}
	if got := stats.snapshot(); got.ResponseSent != 1 || got.AFPacketTX != 1 || got.AFXDPTX != 0 {
		t.Fatalf("stats = %+v, want response_sent=1 afpacket_tx=1 afxdp_tx=0", got)
	}
}

func TestResponseExecutorTracksAFPacketFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("afpacket failed")
	results := newTestResultBuffer(t, 4)
	tx := &stubFrameTransmitter{err: wantErr}
	stats := newStatsCounters()
	executor, err := NewResponseExecutor(ResponseExecutorConfig{
		IfIndex: 7,
		QueueID: 3,
		Sender: &afpacketSender{
			out: tx,
			buildOpts: BuildOptions{
				HardwareAddr: testHWAddr,
			},
		},
		Results: results,
		Stats:   stats,
	})
	if err != nil {
		t.Fatalf("NewResponseExecutor() error = %v", err)
	}

	err = executor.Execute(context.Background(), XSKMetadata{
		RuleID: 1008,
		Action: ActionARPReply,
	}, buildTestARPRequest(t))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Execute() error = %v, want %v", err, wantErr)
	}

	recorded := results.List()
	if len(recorded) != 1 || recorded[0].TXBackend != TXBackendAFPacket || recorded[0].Result != ResultFailed {
		t.Fatalf("results = %+v, want one failed afpacket result", recorded)
	}
	if got := stats.snapshot(); got.ResponseFailed != 1 || got.AFPacketTXFailed != 1 || got.AFXDPTXFailed != 0 {
		t.Fatalf("stats = %+v, want response_failed=1 afpacket_tx_failed=1 afxdp_tx_failed=0", got)
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
	if recorded[0].TXBackend != TXBackendAFXDP {
		t.Fatalf("result backend = %q, want %q", recorded[0].TXBackend, TXBackendAFXDP)
	}
	if got := executor.stats.snapshot(); got.ResponseSent != 1 || got.AFXDPTX != 1 {
		t.Fatalf("stats = %+v, want response_sent=1 afxdp_tx=1", got)
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
		Stats:   newStatsCounters(),
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
