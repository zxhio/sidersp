package xsk

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
	"sidersp/internal/xsk/afxdp"
)

type SocketFactory func(queueID int) (Socket, error)

type RuntimeDeps struct {
	Registrar Registrar
	Consumers Consumers
	NewSocket SocketFactory
}

type Runtime struct {
	group   *WorkerGroup
	sockets []Socket
	ifindex int
	queues  []int
}

func NewRuntime(opts Options, deps RuntimeDeps) (*Runtime, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	if deps.Registrar == nil {
		return nil, fmt.Errorf("create xsk runtime: registrar is required")
	}

	dispatcher, err := NewDispatcher(deps.Consumers)
	if err != nil {
		return nil, err
	}

	newSocket := deps.NewSocket
	if newSocket == nil {
		newSocket = func(queueID int) (Socket, error) {
			return afxdp.NewSocket(opts.AFXDP, queueID)
		}
	}

	workerSpecs := make([]WorkerSpec, 0, len(opts.Queues))
	sockets := make([]Socket, 0, len(opts.Queues))
	for _, queueID := range opts.Queues {
		socket, err := newSocket(queueID)
		if err != nil {
			closeSockets(sockets)
			return nil, fmt.Errorf("create xsk queue %d: %w", queueID, err)
		}
		sockets = append(sockets, socket)

		worker, err := NewWorker(opts.IfIndex, queueID, deps.Registrar, socket, dispatcher.Dispatch)
		if err != nil {
			closeSockets(sockets)
			return nil, err
		}
		workerSpecs = append(workerSpecs, WorkerSpec{QueueID: queueID, Worker: worker})
	}

	group, err := NewWorkerGroup(workerSpecs)
	if err != nil {
		closeSockets(sockets)
		return nil, err
	}

	return &Runtime{
		group:   group,
		sockets: sockets,
		ifindex: opts.IfIndex,
		queues:  append([]int(nil), opts.Queues...),
	}, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("run xsk runtime: nil runtime")
	}
	defer r.Close()

	logs.App().WithFields(logrus.Fields{
		"ifindex": r.ifindex,
		"queues":  r.queues,
	}).Info("Started xsk runtime")

	return r.group.Run(ctx)
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	var firstErr error
	for _, socket := range r.sockets {
		if err := socket.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.sockets = nil
	return firstErr
}

func closeSockets(sockets []Socket) {
	for _, socket := range sockets {
		_ = socket.Close()
	}
}
