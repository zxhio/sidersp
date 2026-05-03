package analysis

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"sidersp/internal/afpacket"
	"sidersp/internal/logs"
	"sidersp/internal/xsk"
)

const defaultQueueSize = 256

var ErrQueueFull = errors.New("analysis queue is full")

type queueShard struct {
	queue   chan xsk.Envelope
	started bool
}

type Runtime struct {
	mu        sync.Mutex
	queues    map[int]*queueShard
	queueSize int
	runCtx    context.Context
	wg        sync.WaitGroup
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
		queues:    make(map[int]*queueShard),
		queueSize: opts.QueueSize,
		sender:    sender,
		ifaceName: opts.Interface,
	}, nil
}

func (r *Runtime) SubmitXSK(_ context.Context, envelope xsk.Envelope) error {
	if r == nil {
		return fmt.Errorf("submit xsk analysis: nil runtime")
	}

	shard, runCtx, shouldStart := r.shardForQueue(envelope.QueueID)
	if shouldStart {
		r.startShardWorker(runCtx, envelope.QueueID, shard)
	}

	select {
	case shard <- envelope:
		return nil
	default:
		return ErrQueueFull
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	if r == nil {
		return fmt.Errorf("run analysis runtime: nil runtime")
	}

	runCtx, shards := r.start(ctx)
	for queueID, shard := range shards {
		r.startShardWorker(runCtx, queueID, shard)
	}

	<-runCtx.Done()
	r.wg.Wait()
	return nil
}

func (r *Runtime) Close() error {
	if r == nil || r.sender == nil {
		return nil
	}
	return r.sender.Close()
}

func (r *Runtime) start(ctx context.Context) (context.Context, map[int]chan xsk.Envelope) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.runCtx == nil {
		r.runCtx = ctx
	}

	shards := make(map[int]chan xsk.Envelope, len(r.queues))
	for queueID, shard := range r.queues {
		if shard.started {
			continue
		}
		shard.started = true
		shards[queueID] = shard.queue
	}
	return r.runCtx, shards
}

func (r *Runtime) shardForQueue(queueID int) (chan xsk.Envelope, context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	shard, ok := r.queues[queueID]
	if !ok {
		shard = &queueShard{queue: make(chan xsk.Envelope, r.queueSize)}
		r.queues[queueID] = shard
	}
	if r.runCtx == nil || shard.started {
		return shard.queue, nil, false
	}
	shard.started = true
	return shard.queue, r.runCtx, true
}

func (r *Runtime) startShardWorker(ctx context.Context, queueID int, queue <-chan xsk.Envelope) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case envelope := <-queue:
				if err := r.sender.SendFrame(ctx, envelope.Frame); err != nil {
					if ctx.Err() != nil {
						return
					}
					logs.App().WithFields(logrus.Fields{
						"queue":     queueID,
						"rule_id":   envelope.Metadata.RuleID,
						"action":    envelope.Metadata.Action,
						"interface": r.ifaceName,
					}).WithError(err).Warn("Fail to export analysis packet")
				}
			}
		}
	}()
}
