package response

import (
	"context"
	"fmt"
	"io"
	"net"
)

type XSKBackend interface {
	FD() uint32
	Receive(context.Context) ([]byte, error)
	ResponseTransmitter
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
	Registrar            XSKRegistrar
	NewXSKBackend        NewXSKBackendFunc
}

type Runtime struct {
	group    *WorkerGroup
	results  *ResultBuffer
	backends []XSKBackend
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
	for _, queueID := range queues {
		backend, err := config.NewXSKBackend(queueID)
		if err != nil {
			closeBackends(backends)
			return nil, fmt.Errorf("create xsk backend queue %d: %w", queueID, err)
		}
		backends = append(backends, backend)
		executor, err := NewResponseExecutor(ResponseExecutorConfig{
			IfIndex: config.IfIndex,
			QueueID: queueID,
			Options: BuildOptions{
				HardwareAddr: append(net.HardwareAddr(nil), config.HardwareAddr...),
				TCPSeq:       config.TCPSeq,
			},
			TX:      backend,
			Results: results,
		})
		if err != nil {
			closeBackends(backends)
			return nil, err
		}
		worker, err := NewXSKWorker(config.IfIndex, queueID, config.Registrar, backend, executor.ExecuteXSKFrame)
		if err != nil {
			closeBackends(backends)
			return nil, err
		}
		workerSpecs = append(workerSpecs, WorkerSpec{QueueID: queueID, Worker: worker})
	}

	group, err := NewWorkerGroup(workerSpecs)
	if err != nil {
		closeBackends(backends)
		return nil, err
	}
	return &Runtime{group: group, results: results, backends: backends}, nil
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
