package analysis

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/afpacket"
	"sidersp/internal/logs"
	"sidersp/internal/xsk"
)

const defaultQueueSize = 256

var ErrQueueFull = errors.New("analysis queue is full")

type Runtime struct {
	queue     chan xsk.Envelope
	sender    frameSender
	ifaceName string
}

func NewRuntime(opts Options) (*Runtime, error) {
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	sender := opts.sender
	if sender == nil {
		var err error
		sender, err = afpacket.New(opts.Interface)
		if err != nil {
			return nil, err
		}
	}

	return &Runtime{
		queue:     make(chan xsk.Envelope, opts.QueueSize),
		sender:    sender,
		ifaceName: opts.Interface,
	}, nil
}

func (r *Runtime) SubmitXSK(_ context.Context, envelope xsk.Envelope) error {
	if r == nil {
		return fmt.Errorf("submit xsk analysis: nil runtime")
	}
	select {
	case r.queue <- envelope:
		return nil
	default:
		return ErrQueueFull
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("run analysis runtime: nil runtime")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case envelope := <-r.queue:
			if err := r.sender.SendFrame(ctx, envelope.Frame); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				logs.App().WithFields(logrus.Fields{
					"queue":     envelope.QueueID,
					"rule_id":   envelope.Metadata.RuleID,
					"action":    envelope.Metadata.Action,
					"interface": r.ifaceName,
				}).WithError(err).Warn("Fail to export analysis packet")
			}
		}
	}
}

func (r *Runtime) Close() error {
	if r == nil || r.sender == nil {
		return nil
	}
	return r.sender.Close()
}
