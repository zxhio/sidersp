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
	handler XSKFrameHandler
	frames  [][]byte
}

func (s *stubSocket) FD() uint32 { return s.fd }

func (s *stubSocket) Run(_ context.Context, handler XSKFrameHandler) error {
	s.calls++
	s.handler = handler
	for _, frame := range s.frames {
		if err := handler.ExecuteXSKFrame(context.Background(), frame); err != nil {
			return err
		}
	}
	return s.err
}

type stubFrameHandler struct {
	err    error
	frames [][]byte
}

func (s *stubFrameHandler) ExecuteXSKFrame(_ context.Context, frame []byte) error {
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

func TestDecodeXSKMetadata(t *testing.T) {
	t.Parallel()

	frame := []byte{
		0x04, 0x03, 0x02, 0x01,
		0x05, 0x00,
		0x00, 0x00,
		0xaa, 0xbb,
	}

	meta, payload, err := DecodeXSKMetadata(frame)
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

func TestXSKWorkerRegistersSocketBeforeRun(t *testing.T) {
	t.Parallel()

	registrar := &stubRegistrar{}
	socket := &stubSocket{fd: 42}
	handler := &stubFrameHandler{}
	worker, err := NewXSKWorker(7, 3, registrar, socket, handler)
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if registrar.calls != 1 || registrar.queueID != 3 || registrar.fd != 42 {
		t.Fatalf("registrar = %+v, want queue=3 fd=42 calls=1", registrar)
	}
	if socket.calls != 1 {
		t.Fatalf("socket calls = %d, want 1", socket.calls)
	}
	if socket.handler != handler {
		t.Fatalf("socket handler = %p, want %p", socket.handler, handler)
	}
}

func TestXSKWorkerReturnsRegisterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("register failed")
	registrar := &stubRegistrar{err: wantErr}
	socket := &stubSocket{fd: 42}
	worker, err := NewXSKWorker(7, 3, registrar, socket, &stubFrameHandler{})
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
	socket := &stubSocket{
		fd:     42,
		frames: [][]byte{{0x01, 0x02}, {0x03, 0x04}},
	}
	handler := &stubFrameHandler{}
	worker, err := NewXSKWorker(7, 3, registrar, socket, handler)
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	if err := worker.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(handler.frames) != 2 {
		t.Fatalf("handler frames = %d, want 2", len(handler.frames))
	}
	if string(handler.frames[0]) != string([]byte{0x01, 0x02}) || string(handler.frames[1]) != string([]byte{0x03, 0x04}) {
		t.Fatalf("handler frames = %x, want dispatched socket frames", handler.frames)
	}
}

func TestXSKWorkerReturnsFrameHandlerError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("handle failed")
	registrar := &stubRegistrar{}
	socket := &stubSocket{
		fd:     42,
		frames: [][]byte{{0x01, 0x02}},
	}
	handler := &stubFrameHandler{err: wantErr}
	worker, err := NewXSKWorker(7, 3, registrar, socket, handler)
	if err != nil {
		t.Fatalf("NewXSKWorker() error = %v", err)
	}

	err = worker.Run(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
}

func TestNewXSKWorkerValidation(t *testing.T) {
	t.Parallel()

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
			handler: &stubFrameHandler{},
			queueID: 0,
			want:    "registrar is required",
		},
		{
			name:      "missing socket",
			registrar: &stubRegistrar{},
			handler:   &stubFrameHandler{},
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
			handler:   &stubFrameHandler{},
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
