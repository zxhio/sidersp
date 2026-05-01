package response

import (
	"context"
	"net"
	"testing"

	"sidersp/internal/config"
	"sidersp/internal/model"
	"sidersp/internal/xsk"
)

type stubXSKSocket struct {
	fd         uint32
	closeCalls int
	txFrames   [][]byte
}

func (s *stubXSKSocket) FD() uint32 { return s.fd }

func (s *stubXSKSocket) Receive(context.Context) ([]byte, error) {
	return nil, context.Canceled
}

func (s *stubXSKSocket) SendFrame(_ context.Context, frame []byte) error {
	s.txFrames = append(s.txFrames, append([]byte(nil), frame...))
	return nil
}

func (s *stubXSKSocket) Close() error {
	s.closeCalls++
	return nil
}

func normalizeTestOptions(opts Options) Options {
	opts = normalizeOptions(opts)
	if opts.IfIndex <= 0 {
		opts.IfIndex = 7
	}
	if len(opts.HardwareAddr) == 0 {
		opts.HardwareAddr = append(net.HardwareAddr(nil), testHWAddr...)
	}
	return opts
}

func TestNewRuntimeUsesDefaults(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(normalizeTestOptions(Options{}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
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
		config.XSKConfig{},
	)
	if err != nil {
		t.Fatalf("NewOptions() error = %v", err)
	}
	if opts.Enabled {
		t.Fatalf("NewOptions() = %+v, want disabled options", opts)
	}
}

func TestResolveTXHardwareAddrUsesInterfaceDefault(t *testing.T) {
	t.Parallel()

	txIface := net.Interface{
		Name:         "eth-test0",
		HardwareAddr: testHWAddr,
	}

	defaulted, err := resolveTXHardwareAddr(txIface)
	if err != nil {
		t.Fatalf("resolveTXHardwareAddr() error = %v", err)
	}
	if got := defaulted.String(); got != testHWAddr.String() {
		t.Fatalf("default hardware addr = %s, want %s", got, testHWAddr)
	}
}

func TestRuntimeHandleXSKSendsResponse(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(normalizeTestOptions(Options{}))
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	socket := &stubXSKSocket{fd: 42}
	envelope := xsk.Envelope{
		QueueID: 3,
		Metadata: xsk.Metadata{
			RuleID: 1001,
			Action: ActionICMPEchoReply,
		},
		Frame: buildTestICMPEchoRequest(t),
	}
	if err := runtime.HandleXSK(context.Background(), envelope, socket); err != nil {
		t.Fatalf("HandleXSK() error = %v", err)
	}
	if len(socket.txFrames) != 1 {
		t.Fatalf("tx frames = %d, want 1", len(socket.txFrames))
	}
	results := runtime.Results()
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if results[0].RXQueue != 3 || results[0].RuleID != 1001 || results[0].Result != ResultSent {
		t.Fatalf("result = %+v, want queue=3 rule=1001 sent", results[0])
	}
}

func TestRuntimeResultsReturnsCopy(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(normalizeTestOptions(Options{}))
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

	runtime, err := NewRuntime(normalizeTestOptions(Options{}))
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

	runtime, err := NewRuntime(normalizeTestOptions(Options{}))
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

	_, err := NewRuntime(Options{})
	if err == nil {
		t.Fatal("NewRuntime() error = nil, want validation error")
	}
}
