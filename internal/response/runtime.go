package response

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
)

type XSKBackend interface {
	FD() uint32
	Receive(context.Context) ([]byte, error)
	frameTransmitter
	io.Closer
}

// NewXSKBackendFunc creates an XSKBackend for the given queue ID.
type NewXSKBackendFunc func(queueID int) (XSKBackend, error)

type RuntimeConfig struct {
	IfIndex              int
	Queues               []int
	ResultBufferCapacity int
	HardwareAddr         net.HardwareAddr
	TCPSeq               uint32
	EgressInterface      string
	Registrar            XSKRegistrar
	NewXSKBackend        NewXSKBackendFunc
}

type Runtime struct {
	group    *WorkerGroup
	results  *ResultBuffer
	backends []XSKBackend
	closers  []io.Closer
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if config.Registrar == nil {
		return nil, fmt.Errorf("create response runtime: registrar is required")
	}
	if config.NewXSKBackend == nil {
		return nil, fmt.Errorf("create response runtime: xsk backend is required")
	}

	capacity := config.ResultBufferCapacity
	if capacity <= 0 {
		capacity = 1024
	}
	results, err := NewResultBuffer(capacity)
	if err != nil {
		return nil, err
	}

	queues := config.Queues
	if len(queues) == 0 {
		queues = []int{0}
	}
	workerSpecs := make([]WorkerSpec, 0, len(queues))
	backends := make([]XSKBackend, 0, len(queues))
	closers := make([]io.Closer, 0, 2)
	actionOverrides := make(map[uint16]actionTransmitter)
	if strings.TrimSpace(config.EgressInterface) != "" {
		icmpTX, err := newICMPEgressSender(config.EgressInterface)
		if err != nil {
			return nil, fmt.Errorf("create icmp egress transmitter: %w", err)
		}
		closers = append(closers, icmpTX)
		actionOverrides[ActionICMPEchoReply] = &icmpEgressTX{tx: icmpTX}

		arpTX, err := newFrameEgressSender(config.EgressInterface)
		if err != nil {
			closeClosers(closers)
			return nil, fmt.Errorf("create arp egress transmitter: %w", err)
		}
		closers = append(closers, arpTX)
		actionOverrides[ActionARPReply] = &arpEgressTX{tx: arpTX}
	}
	for _, queueID := range queues {
		backend, err := config.NewXSKBackend(queueID)
		if err != nil {
			closeBackends(backends)
			closeClosers(closers)
			return nil, fmt.Errorf("create xsk backend queue %d: %w", queueID, err)
		}
		backends = append(backends, backend)
		var actionTX actionTransmitter = &sameInterfaceTX{tx: backend}
		if len(actionOverrides) != 0 {
			actionTX = &actionTXMux{defaultTX: actionTX, overrides: actionOverrides}
		}
		executor, err := NewResponseExecutor(ResponseExecutorConfig{
			IfIndex: config.IfIndex,
			QueueID: queueID,
			Options: BuildOptions{
				HardwareAddr: append(net.HardwareAddr(nil), config.HardwareAddr...),
				TCPSeq:       config.TCPSeq,
			},
			TX:      actionTX,
			Results: results,
		})
		if err != nil {
			closeBackends(backends)
			closeClosers(closers)
			return nil, err
		}
		worker, err := NewXSKWorker(config.IfIndex, queueID, config.Registrar, backend, executor.ExecuteXSKFrame)
		if err != nil {
			closeBackends(backends)
			closeClosers(closers)
			return nil, err
		}
		workerSpecs = append(workerSpecs, WorkerSpec{QueueID: queueID, Worker: worker})
	}

	group, err := NewWorkerGroup(workerSpecs)
	if err != nil {
		closeBackends(backends)
		closeClosers(closers)
		return nil, err
	}
	return &Runtime{group: group, results: results, backends: backends, closers: closers}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("run response runtime: nil runtime")
	}
	defer r.Close()
	return r.group.Run(ctx)
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var firstErr error
	for _, backend := range r.backends {
		if err := backend.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.backends = nil
	for _, closer := range r.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.closers = nil
	return firstErr
}

func (r *Runtime) Results() []ResponseResult {
	if r == nil {
		return nil
	}
	return r.results.List()
}

func closeBackends(backends []XSKBackend) {
	for _, backend := range backends {
		_ = backend.Close()
	}
}

func closeClosers(closers []io.Closer) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}
