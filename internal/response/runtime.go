package response

import (
	"context"
	"fmt"
	"io"
	"net"

	"sidersp/internal/frameio"
	"sidersp/internal/model"
	"sidersp/internal/rule"
	"sidersp/internal/xsk"
)

type Runtime struct {
	results      *ResultBuffer
	stats        *statsCounters
	closers      []io.Closer
	ruleConfigs  *RuleConfigStore
	ifindex      int
	buildOpts    BuildOptions
	egressWriter frameio.WriteCloser
}

func NewRuntime(opts Options, egressWriter frameio.WriteCloser) (*Runtime, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	if opts.EgressInterface == "" && egressWriter != nil {
		return nil, fmt.Errorf("create response runtime: egress writer requires egress interface")
	}
	if opts.EgressInterface != "" && egressWriter == nil {
		return nil, fmt.Errorf("create response runtime: egress writer is required")
	}

	results, err := NewResultBuffer(opts.ResultBufferSize)
	if err != nil {
		return nil, err
	}
	stats := newStatsCounters()

	closers := make([]io.Closer, 0, 1)
	ruleConfigs := NewRuleConfigStore()
	buildOpts := BuildOptions{
		HardwareAddr: append(net.HardwareAddr(nil), opts.HardwareAddr...),
		RuleConfigs:  ruleConfigs,
	}
	if egressWriter != nil {
		closers = append(closers, egressWriter)
	}

	return &Runtime{
		results:      results,
		stats:        stats,
		closers:      closers,
		ruleConfigs:  ruleConfigs,
		ifindex:      opts.IfIndex,
		buildOpts:    buildOpts,
		egressWriter: egressWriter,
	}, nil
}

func buildResponseSender(socket xsk.Socket, egressWriter frameio.WriteCloser, buildOpts BuildOptions) responseSender {
	if egressWriter == nil {
		return &responseTXSender{
			backend:   TXBackendAFXDP,
			out:       socket,
			buildOpts: buildOpts,
		}
	}
	return &responseTXSender{
		backend:   TXBackendAFPacket,
		out:       egressWriter,
		buildOpts: buildOpts,
	}
}

func (r *Runtime) Close() error {
	var firstErr error
	for _, closer := range r.closers {
		if err := closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.closers = nil
	return firstErr
}

func (r *Runtime) HandleXSK(ctx context.Context, envelope xsk.Envelope, socket xsk.Socket) error {
	executor, err := NewResponseExecutor(ResponseExecutorConfig{
		IfIndex: r.ifindex,
		QueueID: envelope.QueueID,
		Sender:  buildResponseSender(socket, r.egressWriter, r.buildOpts),
		Results: r.results,
		Stats:   r.stats,
	})
	if err != nil {
		return err
	}
	return executor.Execute(ctx, envelope.Metadata, envelope.Frame)
}

func (r *Runtime) Results() []ResponseResult {
	return r.results.List()
}

func (r *Runtime) ReplaceRules(set rule.RuleSet) error {
	return r.ruleConfigs.ReplaceRules(set)
}

func (r *Runtime) ReadStats() model.ResponseStats {
	return r.stats.snapshot()
}

func (r *Runtime) ResetStats() error {
	r.stats.reset()
	return nil
}
