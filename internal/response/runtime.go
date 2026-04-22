package response

import (
	"context"
	"fmt"
	"net"
)

type XSKBackend interface {
	XSKSocket
	ResponseTransmitter
}

type XSKBackendFactory interface {
	NewXSKBackend(queueID int) (XSKBackend, error)
}

type RuntimeConfig struct {
	IfIndex              int
	Queues               []int
	ResultBufferCapacity int
	HardwareAddr         net.HardwareAddr
	TCPSeq               uint32
	Registrar            XSKRegistrar
	BackendFactory       XSKBackendFactory
}

type Runtime struct {
	group   *WorkerGroup
	results *ResultBuffer
}

func NewRuntime(config RuntimeConfig) (*Runtime, error) {
	if config.Registrar == nil {
		return nil, fmt.Errorf("create response runtime: registrar is required")
	}
	if config.BackendFactory == nil {
		return nil, fmt.Errorf("create response runtime: backend factory is required")
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
	for _, queueID := range queues {
		backend, err := config.BackendFactory.NewXSKBackend(queueID)
		if err != nil {
			return nil, fmt.Errorf("create xsk backend queue %d: %w", queueID, err)
		}
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
			return nil, err
		}
		worker, err := NewXSKWorker(config.IfIndex, queueID, config.Registrar, backend, executor)
		if err != nil {
			return nil, err
		}
		workerSpecs = append(workerSpecs, WorkerSpec{QueueID: queueID, Worker: worker})
	}

	group, err := NewWorkerGroup(workerSpecs)
	if err != nil {
		return nil, err
	}
	return &Runtime{group: group, results: results}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("run response runtime: nil runtime")
	}
	return r.group.Run(ctx)
}

func (r *Runtime) Results() []ResponseResult {
	if r == nil {
		return nil
	}
	return r.results.List()
}
