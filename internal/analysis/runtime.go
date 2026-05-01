package analysis

import (
	"context"
	"errors"
	"fmt"

	"sidersp/internal/xsk"
)

const defaultQueueSize = 256

var ErrQueueFull = errors.New("analysis queue is full")

type Options struct {
	QueueSize int
}

type Runtime struct {
	queue chan xsk.Envelope
}

func NewRuntime(opts Options) (*Runtime, error) {
	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	return &Runtime{
		queue: make(chan xsk.Envelope, queueSize),
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
		case <-r.queue:
		}
	}
}
