package response

import (
	"context"
	"testing"
)

var (
	benchmarkFrameSink []byte
	benchmarkErrSink   error
)

type benchmarkTransmitter struct {
	lastFrame []byte
	count     int
}

func (t *benchmarkTransmitter) Transmit(_ context.Context, frame []byte) error {
	t.lastFrame = frame
	t.count++
	return nil
}

func (t *benchmarkTransmitter) TransmitBorrowed(_ context.Context, frame []byte) error {
	t.lastFrame = frame
	t.count++
	return nil
}

func BenchmarkBuildICMPEchoReply(b *testing.B) {
	benchmarkBuildResponseFrame(b, XSKMetadata{Action: ActionICMPEchoReply}, buildTestICMPEchoRequest(b), BuildOptions{})
}

func BenchmarkBuildARPReply(b *testing.B) {
	benchmarkBuildResponseFrame(b, XSKMetadata{Action: ActionARPReply}, buildTestARPRequest(b), BuildOptions{
		HardwareAddr: testHWAddr,
	})
}

func BenchmarkBuildTCPSynAck(b *testing.B) {
	benchmarkBuildResponseFrame(b, XSKMetadata{Action: ActionTCPSynAck}, buildTestTCPSyn(b), BuildOptions{
		TCPSeq: 1000,
	})
}

func BenchmarkExecuteICMPEchoReply(b *testing.B) {
	benchmarkExecuteResponseFrame(b, XSKMetadata{
		RuleID: 1001,
		Action: ActionICMPEchoReply,
	}, buildTestICMPEchoRequest(b), BuildOptions{})
}

func BenchmarkExecuteARPReply(b *testing.B) {
	benchmarkExecuteResponseFrame(b, XSKMetadata{
		RuleID: 1002,
		Action: ActionARPReply,
	}, buildTestARPRequest(b), BuildOptions{
		HardwareAddr: testHWAddr,
	})
}

func BenchmarkExecuteTCPSynAck(b *testing.B) {
	benchmarkExecuteResponseFrame(b, XSKMetadata{
		RuleID: 1003,
		Action: ActionTCPSynAck,
	}, buildTestTCPSyn(b), BuildOptions{
		TCPSeq: 1000,
	})
}

func benchmarkBuildResponseFrame(b *testing.B, meta XSKMetadata, request []byte, opts BuildOptions) {
	b.Helper()

	b.ReportAllocs()
	b.SetBytes(int64(len(request)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		frame, err := BuildResponseFrame(meta, request, opts)
		if err != nil {
			b.Fatalf("BuildResponseFrame() error = %v", err)
		}
		benchmarkFrameSink = frame
	}
}

func benchmarkExecuteResponseFrame(b *testing.B, meta XSKMetadata, request []byte, opts BuildOptions) {
	b.Helper()

	frame := buildTestXSKFrame(b, meta, request)
	results := newTestResultBuffer(b, 1024)
	tx := &benchmarkTransmitter{}
	executor := newTestExecutor(b, tx, results, opts)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := executor.ExecuteXSKFrame(context.Background(), frame)
		if err != nil {
			b.Fatalf("ExecuteXSKFrame() error = %v", err)
		}
	}

	benchmarkFrameSink = tx.lastFrame
	benchmarkErrSink = nil
}
