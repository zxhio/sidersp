package response

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

func (s *stubRegistrar) RegisterXSKSocket(queueID int, fd uint32) error {
	s.queueID = queueID
	s.fd = fd
	s.calls++
	return s.err
}

type stubSocket struct {
	fd    uint32
	err   error
	calls int
}

func (s *stubSocket) FD() uint32 { return s.fd }

func (s *stubSocket) Run(context.Context) error {
	s.calls++
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
	worker, err := NewXSKWorker(7, 3, registrar, socket)
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
}

func TestXSKWorkerReturnsRegisterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("register failed")
	registrar := &stubRegistrar{err: wantErr}
	socket := &stubSocket{fd: 42}
	worker, err := NewXSKWorker(7, 3, registrar, socket)
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
