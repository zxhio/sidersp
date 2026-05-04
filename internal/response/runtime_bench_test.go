package response

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
	"sidersp/internal/xsk"
)

type benchmarkXSKSocket struct {
	fd uint32
}

func (s *benchmarkXSKSocket) FD() uint32 { return s.fd }

func (s *benchmarkXSKSocket) ReadFrame(context.Context) ([]byte, error) {
	return nil, context.Canceled
}

func (s *benchmarkXSKSocket) WriteFrame(context.Context, []byte) error {
	return nil
}

func (s *benchmarkXSKSocket) WriteBorrowedFrame(context.Context, []byte) error {
	return nil
}

func (s *benchmarkXSKSocket) Close() error { return nil }

func BenchmarkRuntimeHandleXSKICMPEchoReply(b *testing.B) {
	runtime, err := NewRuntime(normalizeTestOptions(Options{}), nil)
	if err != nil {
		b.Fatalf("NewRuntime() error = %v", err)
	}

	socket := &benchmarkXSKSocket{fd: 42}
	envelope := xsk.Envelope{
		QueueID: 3,
		Metadata: xsk.Metadata{
			RuleID: 1001,
			Action: ActionICMPEchoReply,
		},
		Frame: buildTestICMPEchoRequest(b),
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(envelope.Frame) + xsk.MetadataSize))
	b.ResetTimer()

	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		if err := runtime.HandleXSK(ctx, envelope, socket); err != nil {
			b.Fatalf("HandleXSK() error = %v", err)
		}
	}
}

type benchmarkWorkerRegistrar struct{}

func (benchmarkWorkerRegistrar) RegisterXSK(int, uint32) error { return nil }

type benchmarkWorkerSocket struct {
	fd     uint32
	frame  []byte
	limit  int
	count  int
	cancel context.CancelFunc
}

func (s *benchmarkWorkerSocket) FD() uint32 { return s.fd }

func (s *benchmarkWorkerSocket) ReadFrame(ctx context.Context) ([]byte, error) {
	if s.count >= s.limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}

	s.count++
	if s.count == s.limit && s.cancel != nil {
		s.cancel()
	}
	return append([]byte(nil), s.frame...), nil
}

func (s *benchmarkWorkerSocket) ReadBorrowedFrame(ctx context.Context) ([]byte, error) {
	if s.count >= s.limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.Canceled
	}

	s.count++
	if s.count == s.limit && s.cancel != nil {
		s.cancel()
	}
	return s.frame, nil
}

func (s *benchmarkWorkerSocket) ReleaseBorrowedFrame() {}

func (s *benchmarkWorkerSocket) WriteFrame(context.Context, []byte) error {
	return nil
}

func (s *benchmarkWorkerSocket) WriteBorrowedFrame(context.Context, []byte) error {
	return nil
}

func (s *benchmarkWorkerSocket) Close() error { return nil }

func BenchmarkXSKWorkerToResponseICMPEchoReply(b *testing.B) {
	logs.App().SetOutput(io.Discard)
	logs.App().SetLevel(logrus.PanicLevel)

	runtime, err := NewRuntime(normalizeTestOptions(Options{}), nil)
	if err != nil {
		b.Fatalf("NewRuntime() error = %v", err)
	}

	frame := buildTestXSKFrame(b, XSKMetadata{
		RuleID: 1001,
		Action: ActionICMPEchoReply,
	}, buildTestICMPEchoRequest(b))

	dispatcher, err := xsk.NewDispatcher(xsk.Consumers{Response: runtime})
	if err != nil {
		b.Fatalf("NewDispatcher() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socket := &benchmarkWorkerSocket{
		fd:     42,
		frame:  frame,
		limit:  b.N,
		cancel: cancel,
	}

	worker, err := xsk.NewWorker(7, 3, benchmarkWorkerRegistrar{}, socket, dispatcher.Dispatch)
	if err != nil {
		b.Fatalf("NewWorker() error = %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()

	if err := worker.Run(ctx); err != nil {
		b.Fatalf("Run() error = %v", err)
	}
}
