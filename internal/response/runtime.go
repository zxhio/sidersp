package response

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
	"sidersp/internal/model"
	"sidersp/internal/rule"
)

// NewXSKFunc creates a queue-local XSK socket for the given queue ID.
type NewXSKFunc func(queueID int) (XSKSocket, error)

type Runtime struct {
	group           *WorkerGroup
	results         *ResultBuffer
	stats           *responseStatsCounters
	sockets         []XSKSocket
	closers         []io.Closer
	ruleConfigs     *RuleConfigStore
	ifindex         int
	queues          []int
	senderMode      string
	egressInterface string
}

func NewRuntime(opts Options) (*Runtime, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	results, err := NewResultBuffer(opts.ResultBufferSize)
	if err != nil {
		return nil, err
	}
	stats := newResponseStatsCounters()

	queues := opts.Queues
	workerSpecs := make([]WorkerSpec, 0, len(queues))
	sockets := make([]XSKSocket, 0, len(queues))
	closers := make([]io.Closer, 0, 1)
	ruleConfigs := NewRuleConfigStore()
	buildOpts := BuildOptions{
		HardwareAddr: append(net.HardwareAddr(nil), opts.HardwareAddr...),
		RuleConfigs:  ruleConfigs,
	}
	afpacketOut, err := openAFPacketFrameSender(opts.EgressInterface)
	if err != nil {
		return nil, err
	}
	if afpacketOut != nil {
		closers = append(closers, afpacketOut.(io.Closer))
	}
	for _, queueID := range queues {
		socket, err := opts.NewXSK(queueID)
		if err != nil {
			closeSockets(sockets)
			closeClosers(closers)
			return nil, fmt.Errorf("create xsk queue %d: %w", queueID, err)
		}
		sockets = append(sockets, socket)
		sender := buildResponseSender(socket, afpacketOut, buildOpts)
		executor, err := NewResponseExecutor(ResponseExecutorConfig{
			IfIndex: opts.IfIndex,
			QueueID: queueID,
			Sender:  sender,
			Results: results,
			Stats:   stats,
		})
		if err != nil {
			closeSockets(sockets)
			closeClosers(closers)
			return nil, err
		}
		worker, err := NewXSKWorker(opts.IfIndex, queueID, opts.Registrar, socket, executor.ExecuteXSK)
		if err != nil {
			closeSockets(sockets)
			closeClosers(closers)
			return nil, err
		}
		workerSpecs = append(workerSpecs, WorkerSpec{QueueID: queueID, Worker: worker})
	}

	group, err := NewWorkerGroup(workerSpecs)
	if err != nil {
		closeSockets(sockets)
		closeClosers(closers)
		return nil, err
	}
	return &Runtime{
		group:           group,
		results:         results,
		stats:           stats,
		sockets:         sockets,
		closers:         closers,
		ruleConfigs:     ruleConfigs,
		ifindex:         opts.IfIndex,
		queues:          append([]int(nil), queues...),
		senderMode:      responseSenderMode(opts.EgressInterface),
		egressInterface: opts.EgressInterface,
	}, nil
}

func buildResponseSender(socket XSKSocket, afpacketOut frameSender, buildOpts BuildOptions) responseSender {
	if afpacketOut == nil {
		return &afxdpSender{
			out:       socket,
			buildOpts: buildOpts,
		}
	}
	return &afpacketSender{
		out:       afpacketOut,
		buildOpts: buildOpts,
	}
}

func openAFPacketFrameSender(ifaceName string) (frameSender, error) {
	if ifaceName == "" {
		return nil, nil
	}
	frameSender, err := newAFPacketFrameSender(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("create af_packet sender: %w", err)
	}
	return frameSender, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("run response runtime: nil runtime")
	}
	defer r.Close()

	logs.App().WithFields(logrus.Fields{
		"ifindex":          r.ifindex,
		"queues":           r.queues,
		"sender_mode":      r.senderMode,
		"egress_interface": r.egressInterface,
	}).Info("Started response runtime")

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

func (r *Runtime) ReplaceRules(set rule.RuleSet) error {
	if r == nil {
		return nil
	}
	return r.ruleConfigs.ReplaceRules(set)
}

func (r *Runtime) ReadStats() model.ResponseStats {
	if r == nil {
		return model.ResponseStats{}
	}
	return r.stats.snapshot()
}

func (r *Runtime) ResetStats() error {
	if r == nil {
		return nil
	}
	r.stats.reset()
	return nil
}

func closeSockets(sockets []XSKSocket) {
	for _, socket := range sockets {
		_ = socket.Close()
	}
}

func closeClosers(closers []io.Closer) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}

func responseSenderMode(egressInterface string) string {
	if egressInterface == "" {
		return string(TXBackendAFXDP)
	}
	return string(TXBackendAFPacket)
}
