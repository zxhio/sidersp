package xsk

import (
	"context"
	"errors"
	"testing"
)

type stubRegistrar struct {
	queueID int
	fd      uint32
	err     error
	calls   int
}

func (s *stubRegistrar) RegisterXSK(queueID int, fd uint32) error {
	s.queueID = queueID
	s.fd = fd
	s.calls++
	return s.err
}

type stubSocket struct {
	fd          uint32
	err         error
	calls       int
	borrowCalls int
	frames      [][]byte
	onEmpty     func()
}

func (s *stubSocket) FD() uint32 { return s.fd }

func (s *stubSocket) ReadFrame(ctx context.Context) ([]byte, error) {
	s.calls++
	if len(s.frames) > 0 {
		frame := s.frames[0]
		s.frames = s.frames[1:]
		return frame, nil
	}
	if s.onEmpty != nil {
		s.onEmpty()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, s.err
}

func (s *stubSocket) ReadBorrowedFrame(ctx context.Context) ([]byte, error) {
	s.calls++
	s.borrowCalls++
	if len(s.frames) > 0 {
		frame := s.frames[0]
		s.frames = s.frames[1:]
		return frame, nil
	}
	if s.onEmpty != nil {
		s.onEmpty()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, s.err
}

func (s *stubSocket) ReleaseBorrowedFrame() {}

func (s *stubSocket) WriteFrame(_ context.Context, _ []byte) error {
	return nil
}

func (s *stubSocket) Close() error {
	return nil
}

type handledFrame struct {
	queueID int
	data    []byte
}

func newStubHandler() (*[]handledFrame, FrameHandler) {
	frames := &[]handledFrame{}
	return frames, func(_ context.Context, queueID int, _ Socket, data []byte) error {
		*frames = append(*frames, handledFrame{
			queueID: queueID,
			data:    append([]byte(nil), data...),
		})
		return nil
	}
}

func newStubHandlerWithError(err error) FrameHandler {
	return func(_ context.Context, _ int, _ Socket, _ []byte) error { return err }
}

func TestWorkerReturnsRegisterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("register failed")
	registrar := &stubRegistrar{err: wantErr}
	socket := &stubSocket{fd: 42}
	worker, err := NewWorker(7, 3, registrar, socket, func(_ context.Context, _ int, _ Socket, _ []byte) error { return nil })
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}

	err = worker.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
	if socket.calls != 0 {
		t.Fatalf("socket calls = %d, want 0", socket.calls)
	}
}

func TestWorkerDispatchesSocketFrames(t *testing.T) {
	t.Parallel()

	registrar := &stubRegistrar{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := &stubSocket{
		fd:      42,
		frames:  [][]byte{{0x01, 0x02}, {0x03, 0x04}},
		onEmpty: cancel,
	}

	frames, handler := newStubHandler()
	worker, err := NewWorker(7, 3, registrar, socket, handler)
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(*frames) != 2 {
		t.Fatalf("handler frames = %d, want 2", len(*frames))
	}
	if (*frames)[0].queueID != 3 || (*frames)[1].queueID != 3 {
		t.Fatalf("handler queue IDs = %+v, want queue 3", *frames)
	}
	if string((*frames)[0].data) != string([]byte{0x01, 0x02}) || string((*frames)[1].data) != string([]byte{0x03, 0x04}) {
		t.Fatalf("handler frames = %v, want dispatched socket frames", *frames)
	}
}

func TestWorkerContinuesAfterFrameHandlerError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("handle failed")
	registrar := &stubRegistrar{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := &stubSocket{
		fd:      42,
		frames:  [][]byte{{0x01, 0x02}, {0x03, 0x04}},
		onEmpty: cancel,
	}
	worker, err := NewWorker(7, 3, registrar, socket, newStubHandlerWithError(wantErr))
	if err != nil {
		t.Fatalf("NewWorker() error = %v", err)
	}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if socket.calls != 3 {
		t.Fatalf("socket calls = %d, want 3", socket.calls)
	}
}
