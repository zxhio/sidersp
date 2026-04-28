package response

import (
	"context"
	"errors"
	"testing"

	"sidersp/internal/config"
	"sidersp/internal/model"
)

type runtimeStubRegistrar struct {
	queueID int
	fd      uint32
	err     error
	calls   int
}

func (s *runtimeStubRegistrar) RegisterXSK(queueID int, fd uint32) error {
	s.queueID = queueID
	s.fd = fd
	s.calls++
	return s.err
}

type stubBackendFactory struct {
	err      error
	backends map[int]*stubBackend
	queues   []int
}

func normalizeTestOptions(opts Options) Options {
	opts = normalizeOptions(opts)
	if opts.IfIndex <= 0 {
		opts.IfIndex = 7
	}
	return opts
}

func (s *stubBackendFactory) newFunc() NewXSKFunc {
	return func(queueID int) (XSKSocket, error) {
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
}

type stubBackend struct {
	fd           uint32
	receiveCalls int
	closeCalls   int
	txFrames     [][]byte
}

func (s *stubBackend) FD() uint32 { return s.fd }

func (s *stubBackend) Receive(context.Context) ([]byte, error) {
	s.receiveCalls++
	return nil, context.Canceled
}

func (s *stubBackend) SendFrame(_ context.Context, frame []byte) error {
	s.txFrames = append(s.txFrames, append([]byte(nil), frame...))
	return nil
}

func (s *stubBackend) Close() error {
	s.closeCalls++
	return nil
}

func TestNewRuntimeBuildsWorkersForQueues(t *testing.T) {
	t.Parallel()

	registrar := &runtimeStubRegistrar{}
	factory := &stubBackendFactory{}
	runtime, err := NewRuntime(normalizeTestOptions(Options{
		IfIndex:      7,
		Queues:       []int{0, 1},
		HardwareAddr: testHWAddr,
		TCPSeq:       1000,
		Registrar:    registrar,
		NewXSK:       factory.newFunc(),
	}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	if err := runtime.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(factory.backends) != 2 || factory.backends[0].receiveCalls != 1 || factory.backends[1].receiveCalls != 1 {
		t.Fatalf("backend receive calls = %+v, want both queues receive once", factory.backends)
	}
	if registrar.calls != 2 {
		t.Fatalf("registrar calls = %d, want 2", registrar.calls)
	}
	if factory.backends[0].closeCalls != 1 || factory.backends[1].closeCalls != 1 {
		t.Fatalf("backend close calls = %d,%d; want 1,1", factory.backends[0].closeCalls, factory.backends[1].closeCalls)
	}
}

func TestNewRuntimeUsesDefaults(t *testing.T) {
	t.Parallel()

	factory := &stubBackendFactory{}
	runtime, err := NewRuntime(normalizeTestOptions(Options{
		Registrar: &runtimeStubRegistrar{},
		NewXSK:    factory.newFunc(),
	}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if len(factory.queues) != 1 || factory.queues[0] != 0 {
		t.Fatalf("factory queues = %+v, want [0]", factory.queues)
	}
	if runtime.results.capacity != 1024 {
		t.Fatalf("result capacity = %d, want 1024", runtime.results.capacity)
	}
	if got := runtime.ReadStats(); got != (model.ResponseStats{}) {
		t.Fatalf("ReadStats() = %+v, want zero response stats", got)
	}
}

func TestNewOptionsDisabledReturnsDisabledOptions(t *testing.T) {
	t.Parallel()

	opts, err := NewOptions(
		config.DataplaneConfig{Interface: "eth0", CombinedChannels: 2},
		config.EgressConfig{},
		config.ResponseConfig{},
		&runtimeStubRegistrar{},
	)
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if opts.Enabled {
		t.Fatalf("NewOptions() = %+v, want disabled options", opts)
	}
}

func TestNewRuntimeReturnsBackendError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("backend failed")
	_, err := NewRuntime(normalizeTestOptions(Options{
		Queues:    []int{3},
		Registrar: &runtimeStubRegistrar{},
		NewXSK:    (&stubBackendFactory{err: wantErr}).newFunc(),
	}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewRuntime() error = %v, want %v", err, wantErr)
	}
}

func TestRuntimeResultsReturnsCopy(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(normalizeTestOptions(Options{
		Registrar: &runtimeStubRegistrar{},
		NewXSK:    (&stubBackendFactory{}).newFunc(),
	}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if err := runtime.results.Record(ResponseResult{
		RuleID:    1001,
		Action:    "icmp_echo_reply",
		Result:    ResultSent,
		TXBackend: TXBackendAFXDP,
		RXQueue:   0,
	}); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	results := runtime.Results()
	results[0].RuleID = 9999
	if runtime.Results()[0].RuleID != 1001 {
		t.Fatal("Results() returned mutable backing storage")
	}
}

func TestRuntimeReadStatsReturnsResponseCounters(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(normalizeTestOptions(Options{
		Registrar: &runtimeStubRegistrar{},
		NewXSK:    (&stubBackendFactory{}).newFunc(),
	}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	runtime.stats.recordSent(TXBackendAFXDP)
	runtime.stats.recordSent(TXBackendAFPacket)
	runtime.stats.recordFailed(TXBackendAFXDP)
	runtime.stats.recordFailed(TXBackendAFPacket)

	got := runtime.ReadStats()
	if got.ResponseSent != 2 || got.ResponseFailed != 2 {
		t.Fatalf("ReadStats() = %+v, want response_sent=2 response_failed=2", got)
	}
	if got.AFXDPTX != 1 || got.AFXDPTXFailed != 1 {
		t.Fatalf("ReadStats() = %+v, want afxdp counters = 1/1", got)
	}
	if got.AFPacketTX != 1 || got.AFPacketTXFailed != 1 {
		t.Fatalf("ReadStats() = %+v, want afpacket counters = 1/1", got)
	}
}

func TestRuntimeResetStatsClearsResponseCounters(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(normalizeTestOptions(Options{
		Registrar: &runtimeStubRegistrar{},
		NewXSK:    (&stubBackendFactory{}).newFunc(),
	}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	runtime.stats.recordSent(TXBackendAFXDP)
	runtime.stats.recordFailed(TXBackendAFPacket)

	if err := runtime.ResetStats(); err != nil {
		t.Fatalf("ResetStats() error = %v", err)
	}
	if got := runtime.ReadStats(); got != (model.ResponseStats{}) {
		t.Fatalf("ReadStats() after reset = %+v, want zero response stats", got)
	}
}

func TestNewRuntimeRejectsUnnormalizedOptions(t *testing.T) {
	t.Parallel()

	_, err := NewRuntime(Options{
		Registrar: &runtimeStubRegistrar{},
		NewXSK:    (&stubBackendFactory{}).newFunc(),
	})
	if err == nil {
		t.Fatal("NewRuntime() error = nil, want validation error")
	}
}
