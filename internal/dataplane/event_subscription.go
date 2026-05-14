package dataplane

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"

	"sidersp/internal/logs"
	"sidersp/internal/model"
)

const defaultEventSubscriptionBufferSize = 256

type eventReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

func (r *Runtime) startEventStreamLocked() error {
	reader, err := ringbuf.NewReader(r.objs.EventRingbuf)
	if err != nil {
		return fmt.Errorf("open event ringbuf: %w", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	r.eventCancel = cancel

	go func() {
		if err := r.consumeEventReader(runCtx, cancel, reader); err != nil {
			logs.App().WithError(err).Error("Fail to stream dataplane events")
		}
	}()
	return nil
}

func (r *Runtime) setEventStreamCancel(cancel context.CancelFunc) error {
	r.eventMu.Lock()
	defer r.eventMu.Unlock()

	if r.eventClosed {
		return fmt.Errorf("dataplane event stream is closed")
	}
	if r.eventCancel != nil {
		return fmt.Errorf("dataplane event stream is already running")
	}
	r.eventCancel = cancel
	return nil
}

func (r *Runtime) consumeEventReader(ctx context.Context, cancel context.CancelFunc, reader eventReader) error {
	defer cancel()

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	go r.logKernelStats(ctx, statsLogInterval)

	err := r.streamEvents(ctx, reader)
	r.finishEventStream(err)
	return err
}

func (r *Runtime) finishEventStream(err error) {
	r.eventMu.Lock()
	defer r.eventMu.Unlock()

	r.eventCancel = nil
	if err != nil {
		r.eventErr = err
	}
	r.closeEventSubscribersLocked()
}

func (r *Runtime) closeEventStream() {
	r.eventMu.Lock()
	cancel := r.eventCancel
	r.eventClosed = true
	r.closeEventSubscribersLocked()
	r.eventMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

func (r *Runtime) subscribeEventRecordsLocked(ctx context.Context) <-chan model.EventRecord {
	if r.eventSubs == nil {
		r.eventSubs = make(map[uint64]chan model.EventRecord)
	}

	id := r.eventNextID
	r.eventNextID++
	ch := make(chan model.EventRecord, defaultEventSubscriptionBufferSize)
	r.eventSubs[id] = ch

	go func() {
		<-ctx.Done()
		r.removeEventSubscriber(id)
	}()

	return ch
}

func (r *Runtime) removeEventSubscriber(id uint64) {
	r.eventMu.Lock()
	defer r.eventMu.Unlock()

	ch, ok := r.eventSubs[id]
	if !ok {
		return
	}
	delete(r.eventSubs, id)
	close(ch)
}

func (r *Runtime) publishEventRecord(item model.EventRecord) {
	r.eventMu.Lock()
	defer r.eventMu.Unlock()

	for _, ch := range r.eventSubs {
		select {
		case ch <- item:
		default:
		}
	}
}

func (r *Runtime) closeEventSubscribersLocked() {
	for id, ch := range r.eventSubs {
		delete(r.eventSubs, id)
		close(ch)
	}
}
