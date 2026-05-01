package response

import (
	"context"
	"fmt"
	"io"
	"net"

	"sidersp/internal/model"
	"sidersp/internal/rule"
	"sidersp/internal/xsk"
)

type Runtime struct {
	results         *ResultBuffer
	stats           *statsCounters
	closers         []io.Closer
	ruleConfigs     *RuleConfigStore
	ifindex         int
	senderMode      string
	egressInterface string
	buildOpts       BuildOptions
	afpacketOut     frameSender
}

func NewRuntime(opts Options) (*Runtime, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
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
	afpacketOut, err := openAFPacketFrameSender(opts.EgressInterface)
	if err != nil {
		return nil, err
	}
	if afpacketOut != nil {
		closers = append(closers, afpacketOut.(io.Closer))
	}

	return &Runtime{
		results:         results,
		stats:           stats,
		closers:         closers,
		ruleConfigs:     ruleConfigs,
		ifindex:         opts.IfIndex,
		senderMode:      senderMode(opts.EgressInterface),
		egressInterface: opts.EgressInterface,
		buildOpts:       buildOpts,
		afpacketOut:     afpacketOut,
	}, nil
}

func buildResponseSender(socket xsk.Socket, afpacketOut frameSender, buildOpts BuildOptions) responseSender {
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

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
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
	if r == nil {
		return fmt.Errorf("handle xsk response: nil runtime")
	}

	executor, err := NewResponseExecutor(ResponseExecutorConfig{
		IfIndex: r.ifindex,
		QueueID: envelope.QueueID,
		Sender:  buildResponseSender(socket, r.afpacketOut, r.buildOpts),
		Results: r.results,
		Stats:   r.stats,
	})
	if err != nil {
		return err
	}
	return executor.Execute(ctx, envelope.Metadata, envelope.Frame)
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

func closeClosers(closers []io.Closer) {
	for _, closer := range closers {
		_ = closer.Close()
	}
}

func senderMode(egressInterface string) string {
	if egressInterface == "" {
		return string(TXBackendAFXDP)
	}
	return string(TXBackendAFPacket)
}
