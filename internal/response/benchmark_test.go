package response

import (
	"context"
	"testing"
	"time"
)

var (
	benchmarkFrameSink []byte
	benchmarkErrSink   error
)

type benchmarkTransmitter struct {
	lastFrame []byte
	count     int
}

func (t *benchmarkTransmitter) SendFrame(_ context.Context, frame []byte) error {
	t.lastFrame = frame
	t.count++
	return nil
}

func (t *benchmarkTransmitter) SendBorrowedFrame(_ context.Context, frame []byte) error {
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
	benchmarkBuildResponseFrame(b, XSKMetadata{RuleID: 1003, Action: ActionTCPSynAck}, buildTestTCPSyn(b), testTCPSynAckBuildOptions(b, 1003, 1000))
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
	}, buildTestTCPSyn(b), testTCPSynAckBuildOptions(b, 1003, 1000))
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
	benchmarkExecuteXSKFrame(b, executor, frame)

	benchmarkFrameSink = tx.lastFrame
	benchmarkErrSink = nil
}

func benchmarkStartTimer(b *testing.B) time.Time {
	b.Helper()
	return time.Now()
}

func benchmarkStopTimerWithRates(b *testing.B, startedAt time.Time, frameLen int) {
	b.Helper()

	elapsed := time.Since(startedAt)
	b.StopTimer()
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "pps")
	b.ReportMetric(float64(frameLen*8*b.N)/elapsed.Seconds()/1e9, "gbps")
}

func benchmarkExecuteXSKFrame(b *testing.B, executor *ResponseExecutor, frame []byte) {
	b.Helper()

	startedAt := benchmarkStartTimer(b)
	for i := 0; i < b.N; i++ {
		if err := executor.ExecuteXSK(context.Background(), frame); err != nil {
			b.Fatalf("ExecuteXSK() error = %v", err)
		}
	}
	benchmarkStopTimerWithRates(b, startedAt, len(frame))
}
