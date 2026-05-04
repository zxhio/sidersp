package analysis

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"sidersp/internal/frameio"
	"sidersp/internal/logs"
	"sidersp/internal/xsk"
)

const defaultQueueSize = 256

var ErrQueueFull = errors.New("analysis queue is full")

type queuedEnvelope struct {
	envelope xsk.Envelope
	buffer   *queuedFrameBuffer
}

type queuedFrameBuffer struct {
	buf []byte
}

type queueShard struct {
	queue   chan queuedEnvelope
	started bool
}

var queuedFramePool = sync.Pool{
	New: func() any {
		return &queuedFrameBuffer{buf: make([]byte, 0, 2048)}
	},
}

type Runtime struct {
	mu         sync.Mutex
	queues     map[int]*queueShard
	queueSize  int
	runCtx     context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	writer     frameio.WriteCloser
	ifaceName  string
	cpuByQueue map[int]int
}

func NewRuntime(opts Options, writer frameio.WriteCloser) (*Runtime, error) {
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	if writer == nil {
		return nil, fmt.Errorf("create analysis runtime: writer is required")
	}

	return &Runtime{
		queues:     make(map[int]*queueShard),
		queueSize:  opts.QueueSize,
		writer:     writer,
		ifaceName:  opts.Interface,
		cpuByQueue: copyWorkerCPUs(opts.WorkerCPUs),
	}, nil
}

func (r *Runtime) SubmitXSK(ctx context.Context, envelope xsk.Envelope) error {
	ch, runCtx, shouldStart := r.shardForQueue(envelope.QueueID)
	if shouldStart {
		r.startShardWorker(runCtx, envelope.QueueID, ch)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if cap(ch) > 0 && len(ch) == cap(ch) {
		return ErrQueueFull
	}

	item := queuedEnvelope{
		envelope: envelope,
	}
	if len(envelope.Frame) != 0 {
		buffer := acquireQueuedFrameBuffer(len(envelope.Frame))
		copy(buffer.buf, envelope.Frame)
		item.envelope.Frame = buffer.buf
		item.buffer = buffer
	}

	select {
	case ch <- item:
		return nil
	case <-ctx.Done():
		releaseQueuedFrameBuffer(item.buffer)
		return ctx.Err()
	default:
		releaseQueuedFrameBuffer(item.buffer)
		return ErrQueueFull
	}
}

func (r *Runtime) Run(ctx context.Context) error {
	runCtx, shards, err := r.start(ctx)
	if err != nil {
		return err
	}
	for queueID, shard := range shards {
		r.startShardWorker(runCtx, queueID, shard)
	}

	<-runCtx.Done()
	r.wg.Wait()
	return r.writer.Close()
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

func (r *Runtime) start(ctx context.Context) (context.Context, map[int]chan queuedEnvelope, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.runCtx != nil {
		return nil, nil, fmt.Errorf("analysis runtime already running")
	}
	r.runCtx, r.cancel = context.WithCancel(ctx)

	shards := make(map[int]chan queuedEnvelope, len(r.queues))
	for queueID, shard := range r.queues {
		if shard.started {
			continue
		}
		shard.started = true
		shards[queueID] = shard.queue
	}
	return r.runCtx, shards, nil
}

func (r *Runtime) shardForQueue(queueID int) (chan queuedEnvelope, context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	shard, ok := r.queues[queueID]
	if !ok {
		shard = &queueShard{queue: make(chan queuedEnvelope, r.queueSize)}
		r.queues[queueID] = shard
	}
	if r.runCtx == nil || shard.started {
		return shard.queue, nil, false
	}
	shard.started = true
	return shard.queue, r.runCtx, true
}

func (r *Runtime) startShardWorker(ctx context.Context, queueID int, queue <-chan queuedEnvelope) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if cpuID, ok := r.cpuByQueue[queueID]; ok {
			if err := setCurrentThreadAffinity(cpuID); err != nil {
				logs.App().WithFields(logrus.Fields{
					"queue":     queueID,
					"interface": r.ifaceName,
					"cpu":       cpuID,
				}).WithError(err).Warn("Fail to pin analysis worker to cpu")
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case item := <-queue:
				envelope := item.envelope
				if err := r.writer.WriteFrame(ctx, envelope.Frame); err != nil {
					releaseQueuedFrameBuffer(item.buffer)
					if ctx.Err() != nil {
						return
					}
					logs.App().WithFields(logrus.Fields{
						"queue":     queueID,
						"rule_id":   envelope.Metadata.RuleID,
						"action":    envelope.Metadata.Action,
						"interface": r.ifaceName,
					}).WithError(err).Warn("Fail to export analysis packet")
					continue
				}
				releaseQueuedFrameBuffer(item.buffer)
			}
		}
	}()
}

func acquireQueuedFrameBuffer(size int) *queuedFrameBuffer {
	item := queuedFramePool.Get().(*queuedFrameBuffer)
	if cap(item.buf) < size {
		item.buf = make([]byte, size)
	} else {
		item.buf = item.buf[:size]
	}
	return item
}

func releaseQueuedFrameBuffer(item *queuedFrameBuffer) {
	if item == nil {
		return
	}
	if cap(item.buf) > 8192 {
		item.buf = make([]byte, 0, 2048)
	} else {
		item.buf = item.buf[:0]
	}
	queuedFramePool.Put(item)
}

func copyWorkerCPUs(raw map[int]int) map[int]int {
	if len(raw) == 0 {
		return nil
	}

	cpus := make(map[int]int, len(raw))
	for queueID, cpuID := range raw {
		cpus[queueID] = cpuID
	}
	return cpus
}

func setCurrentThreadAffinity(cpuID int) error {
	var cpus unix.CPUSet
	cpus.Zero()
	cpus.Set(cpuID)
	return unix.SchedSetaffinity(0, &cpus)
}
