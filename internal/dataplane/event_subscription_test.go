package dataplane

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/stretchr/testify/require"

	"sidersp/internal/model"
)

func TestEventSubscriptionPublishesDecodedRecords(t *testing.T) {
	reader := newFakeEventReader(ruleEventSample(1002, actionTCPReset, 1))
	runtime := &Runtime{
		events:      newEventBuffer(8),
		matchCounts: make(map[uint32]uint64),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, runtime.setEventStreamCancel(cancel))

	events := runtime.subscribeEventRecordsLocked(ctx)
	done := make(chan error, 1)
	go func() {
		done <- runtime.consumeEventReader(ctx, cancel, reader)
	}()

	got := readDataplaneEvent(t, events)
	require.Equal(t, uint32(1002), got.RuleID)
	require.Equal(t, "tcp_reset", got.Action)
	require.Equal(t, "xdp_tx", got.Verdict)
	require.Equal(t, "10.1.2.3", got.SIP)
	require.Equal(t, "192.168.1.20", got.DIP)
	require.Equal(t, uint16(52345), got.SPort)
	require.Equal(t, uint16(80), got.DPort)
	require.Equal(t, uint8(6), got.IPProto)

	cancel()
	require.NoError(t, <-done)
	require.True(t, reader.closed)
	require.Len(t, runtime.Events(), 1)
}

func TestEventSubscriptionClosesOnContextCancel(t *testing.T) {
	reader := newFakeEventReader()
	runtime := &Runtime{matchCounts: make(map[uint32]uint64)}
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, runtime.setEventStreamCancel(cancel))
	events := runtime.subscribeEventRecordsLocked(ctx)

	done := make(chan error, 1)
	go func() {
		done <- runtime.consumeEventReader(ctx, cancel, reader)
	}()

	cancel()
	require.NoError(t, <-done)
	_, ok := <-events
	require.False(t, ok)
	require.True(t, reader.closed)
}

func TestEventSubscriptionReaderErrorPropagates(t *testing.T) {
	wantErr := errors.New("reader failed")
	reader := &fakeEventReader{err: wantErr}
	runtime := &Runtime{matchCounts: make(map[uint32]uint64)}
	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, runtime.setEventStreamCancel(cancel))

	err := runtime.consumeEventReader(ctx, cancel, reader)

	require.ErrorIs(t, err, wantErr)
	_, subErr := runtime.SubscribeEvents(context.Background())
	require.ErrorContains(t, subErr, "stream dataplane events")
}

func readDataplaneEvent(t *testing.T, events <-chan model.EventRecord) model.EventRecord {
	t.Helper()

	select {
	case item := <-events:
		return item
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for dataplane event")
	}
	return model.EventRecord{}
}

type fakeEventReader struct {
	mu       sync.Mutex
	records  []ringbuf.Record
	err      error
	closed   bool
	closedCh chan struct{}
}

func newFakeEventReader(records ...ringbuf.Record) *fakeEventReader {
	return &fakeEventReader{
		records:  records,
		closedCh: make(chan struct{}),
	}
}

func (r *fakeEventReader) Read() (ringbuf.Record, error) {
	r.mu.Lock()
	if r.closedCh == nil {
		r.closedCh = make(chan struct{})
	}
	if len(r.records) != 0 {
		next := r.records[0]
		r.records = r.records[1:]
		r.mu.Unlock()
		return next, nil
	}
	if r.err != nil {
		r.mu.Unlock()
		return ringbuf.Record{}, r.err
	}
	if r.closed {
		r.mu.Unlock()
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	closedCh := r.closedCh
	r.mu.Unlock()

	<-closedCh
	return ringbuf.Record{}, ringbuf.ErrClosed
}

func (r *fakeEventReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	if r.closedCh == nil {
		r.closedCh = make(chan struct{})
	}
	r.closed = true
	close(r.closedCh)
	return nil
}

func ruleEventSample(ruleID uint32, action uint16, verdict uint8) ringbuf.Record {
	raw := make([]byte, 32)
	binary.LittleEndian.PutUint64(raw[0:8], 123)
	binary.LittleEndian.PutUint32(raw[8:12], ruleID)
	binary.LittleEndian.PutUint32(raw[12:16], 9)
	binary.LittleEndian.PutUint32(raw[16:20], 0x0a010203)
	binary.LittleEndian.PutUint32(raw[20:24], 0xc0a80114)
	binary.LittleEndian.PutUint16(raw[24:26], action)
	binary.LittleEndian.PutUint16(raw[26:28], 52345)
	binary.LittleEndian.PutUint16(raw[28:30], 80)
	raw[30] = verdict
	raw[31] = 6
	return ringbuf.Record{RawSample: raw}
}
