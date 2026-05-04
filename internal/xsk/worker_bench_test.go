package xsk

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
)

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

func (s *benchmarkWorkerSocket) Close() error { return nil }

func BenchmarkWorkerRunDispatchNoop(b *testing.B) {
	logs.App().SetOutput(io.Discard)
	logs.App().SetLevel(logrus.PanicLevel)

	frame := []byte{0xe9, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	socket := &benchmarkWorkerSocket{
		fd:     42,
		frame:  frame,
		limit:  b.N,
		cancel: cancel,
	}
	worker, err := NewWorker(7, 3, &stubRegistrar{}, socket, func(context.Context, int, Socket, []byte) error {
		return nil
	})
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
