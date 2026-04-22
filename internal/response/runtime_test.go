package response

import (
	"context"
	"errors"
	"testing"
)

type stubBackendFactory struct {
	err      error
	backends map[int]*stubBackend
	queues   []int
}

func (s *stubBackendFactory) NewXSKBackend(queueID int) (XSKBackend, error) {
	s.queues = append(s.queues, queueID)
	if s.err != nil {
		return nil, s.err
	}
	backend := &stubBackend{fd: uint32(queueID + 10)}
	if s.backends == nil {
		s.backends = make(map[int]*stubBackend)
	}
	s.backends[queueID] = backend
	return backend, nil
}

type stubBackend struct {
	fd         uint32
	runCalls   int
	txFrames   [][]byte
	runHandler XSKFrameHandler
}

func (s *stubBackend) FD() uint32 { return s.fd }

func (s *stubBackend) Run(_ context.Context, handler XSKFrameHandler) error {
	s.runCalls++
	s.runHandler = handler
	return nil
}

func (s *stubBackend) Transmit(_ context.Context, frame []byte) error {
	s.txFrames = append(s.txFrames, append([]byte(nil), frame...))
	return nil
}

func TestNewRuntimeBuildsWorkersForQueues(t *testing.T) {
	t.Parallel()

	registrar := &stubRegistrar{}
	factory := &stubBackendFactory{}
	runtime, err := NewRuntime(RuntimeConfig{
		IfIndex:        7,
		Queues:         []int{0, 1},
		HardwareAddr:   testHWAddr,
		TCPSeq:         1000,
		Registrar:      registrar,
		BackendFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	if err := runtime.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(factory.backends) != 2 || factory.backends[0].runCalls != 1 || factory.backends[1].runCalls != 1 {
		t.Fatalf("backend run calls = %+v, want both queues run once", factory.backends)
	}
	if registrar.calls != 2 {
		t.Fatalf("registrar calls = %d, want 2", registrar.calls)
	}
}

func TestNewRuntimeUsesDefaults(t *testing.T) {
	t.Parallel()

	factory := &stubBackendFactory{}
	runtime, err := NewRuntime(RuntimeConfig{
		Registrar:      &stubRegistrar{},
		BackendFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if len(factory.queues) != 1 || factory.queues[0] != 0 {
		t.Fatalf("factory queues = %+v, want [0]", factory.queues)
	}
	if runtime.results.capacity != 1024 {
		t.Fatalf("result capacity = %d, want 1024", runtime.results.capacity)
	}
}

func TestNewRuntimeReturnsBackendError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("backend failed")
	_, err := NewRuntime(RuntimeConfig{
		Queues:         []int{3},
		Registrar:      &stubRegistrar{},
		BackendFactory: &stubBackendFactory{err: wantErr},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewRuntime() error = %v, want %v", err, wantErr)
	}
}

func TestRuntimeResultsReturnsCopy(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(RuntimeConfig{
		Registrar:      &stubRegistrar{},
		BackendFactory: &stubBackendFactory{},
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if err := runtime.results.Record(ResponseResult{
		RuleID:  1001,
		Action:  "icmp_echo_reply",
		Result:  ResultSent,
		RXQueue: 0,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	results := runtime.Results()
	results[0].RuleID = 9999
	if runtime.Results()[0].RuleID != 1001 {
		t.Fatal("Results() returned mutable backing storage")
	}
}
