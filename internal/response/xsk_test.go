package response

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type stubRegistrar struct {
	queueID int
	fd      uint32
	err     error
	calls   int
}

func (s *stubRegistrar) RegisterXSKSocket(queueID int, fd uint32) error {
	s.queueID = queueID
	s.fd = fd
	s.calls++
	return s.err
}

type stubSocket struct {
	fd      uint32
	err     error
	calls   int
	frames  [][]byte
	onEmpty func()
}

func (s *stubSocket) FD() uint32 { return s.fd }

func (s *stubSocket) Receive(ctx context.Context) ([]byte, error) {
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

func newStubHandler() (*[]frame, XSKFrameHandler) {
	frames := &[]frame{}
	return frames, func(_ context.Context, data []byte) error {
		*frames = append(*frames, frame{data: append([]byte(nil), data...)})
		return nil
	}
}

func newStubHandlerWithError(err error) XSKFrameHandler {
	return func(_ context.Context, _ []byte) error { return err }
}

type frame struct {
	data []byte
}

func TestDecodeXSKMetadata(t *testing.T) {
	t.Parallel()

	frameData := []byte{
		0x04, 0x03, 0x02, 0x01,
		0x05, 0x00,
		0x00, 0x00,
		0xaa, 0xbb,
	}

	meta, payload, err := DecodeXSKMetadata(frameData)
	if err != nil {
		t.Fatalf("DecodeXSKMetadata() error = %v", err)
	}
	if meta.RuleID != 0x01020304 || meta.Action != 5 || meta.Reserved != 0 {
		t.Fatalf("meta = %+v, want rule_id=0x01020304 action=5 reserved=0", meta)
	}
	if len(payload) != 2 || payload[0] != 0xaa || payload[1] != 0xbb {
		t.Fatalf("payload = %x, want aabb", payload)
	}
}

func TestDecodeXSKMetadataRejectsShortFrame(t *testing.T) {
	t.Parallel()

	_, _, err := DecodeXSKMetadata([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("DecodeXSKMetadata() error = nil, want short frame error")
	}
}

func TestXSKWorkerRegistersSocketBeforeReceive(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registrar := &stubRegistrar{}
	socket := &stubSocket{fd: 42, onEmpty: cancel}
	handler := func(_ context.Context, _ []byte) error { return nil }
	worker, err := NewXSKWorker(7, 3, registrar, socket, handler)
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if registrar.calls != 1 || registrar.queueID != 3 || registrar.fd != 42 {
		t.Fatalf("registrar = %+v, want queue=3 fd=42 calls=1", registrar)
	}
	if socket.calls != 1 {
		t.Fatalf("socket calls = %d, want 1", socket.calls)
	}
}

func TestXSKWorkerReturnsRegisterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("register failed")
	registrar := &stubRegistrar{err: wantErr}
	socket := &stubSocket{fd: 42}
	worker, err := NewXSKWorker(7, 3, registrar, socket, func(_ context.Context, _ []byte) error { return nil })
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	err = worker.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
	if socket.calls != 0 {
		t.Fatalf("socket calls = %d, want 0", socket.calls)
	}
}

func TestXSKWorkerDispatchesSocketFrames(t *testing.T) {
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
	worker, err := NewXSKWorker(7, 3, registrar, socket, handler)
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(*frames) != 2 {
		t.Fatalf("handler frames = %d, want 2", len(*frames))
	}
	if string((*frames)[0].data) != string([]byte{0x01, 0x02}) || string((*frames)[1].data) != string([]byte{0x03, 0x04}) {
		t.Fatalf("handler frames = %v, want dispatched socket frames", *frames)
	}
}

func TestXSKWorkerContinuesAfterFrameHandlerError(t *testing.T) {
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
	worker, err := NewXSKWorker(7, 3, registrar, socket, newStubHandlerWithError(wantErr))
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if socket.calls != 3 {
		t.Fatalf("socket calls = %d, want 3", socket.calls)
	}
}

func TestNewXSKWorkerValidation(t *testing.T) {
	t.Parallel()

	noopHandler := XSKFrameHandler(func(_ context.Context, _ []byte) error { return nil })

	tests := []struct {
		name      string
		registrar XSKRegistrar
		socket    XSKSocket
		handler   XSKFrameHandler
		queueID   int
		want      string
	}{
		{
			name:    "missing registrar",
			socket:  &stubSocket{},
			handler: noopHandler,
			queueID: 0,
			want:    "registrar is required",
		},
		{
			name:      "missing socket",
			registrar: &stubRegistrar{},
			handler:   noopHandler,
			queueID:   0,
			want:      "socket is required",
		},
		{
			name:      "missing handler",
			registrar: &stubRegistrar{},
			socket:    &stubSocket{},
			queueID:   0,
			want:      "frame handler is required",
		},
		{
			name:      "negative queue",
			registrar: &stubRegistrar{},
			socket:    &stubSocket{},
			handler:   noopHandler,
			queueID:   -1,
			want:      "queue -1 out of range",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewXSKWorker(7, tc.queueID, tc.registrar, tc.socket, tc.handler)
			if err == nil {
				t.Fatal("NewXSKWorker() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewXSKWorker() error = %q, want %q", err, tc.want)
			}
		})
	}
}
