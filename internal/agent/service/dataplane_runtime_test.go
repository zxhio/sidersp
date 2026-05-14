package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
	"sidersp/internal/model"
)

func TestNewStatsFromDataplaneMapsKernelStats(t *testing.T) {
	got := NewStatsFromDataplane(model.DataplaneStats{
		RXPackets:         100,
		ParseFailed:       2,
		MatchedRules:      30,
		RingbufDropped:    3,
		XDPTX:             11,
		TXFailed:          5,
		XskRedirected:     7,
		XskRedirectFailed: 13,
		RedirectTX:        23,
	})

	require.Equal(t, uint64(100), got.Ingress.Packets)
	require.Equal(t, uint64(2), got.Parse.ErrorPackets)
	require.Equal(t, uint64(30), got.Match.HitPackets)
	require.Equal(t, uint64(11), got.KernelResponse.XDPTXPackets)
	require.Equal(t, uint64(23), got.KernelResponse.RedirectPackets)
	require.Equal(t, uint64(5), got.KernelResponse.ErrorPackets)
	require.Equal(t, uint64(7), got.XSKRedirect.Packets)
	require.Equal(t, uint64(13), got.XSKRedirect.ErrorPackets)
	require.Equal(t, uint64(23), got.Errors.XDPPackets)
	require.Zero(t, got.Errors.XSKPackets)
}

func TestNewStatsFromDataplaneDoesNotExposeDiagnosticsAsDefaultStats(t *testing.T) {
	got := NewStatsFromDataplane(model.DataplaneStats{
		RuleCandidates:       1001,
		XskMetaFailed:        1002,
		XskMapRedirectFailed: 1003,
		RedirectFailed:       1004,
		FibLookupFailed:      1005,
	})

	require.Zero(t, got.Match.MissPackets)
	require.Zero(t, got.UserspaceResponse.Packets)
	require.Zero(t, got.Dispatch.Packets)
	require.Zero(t, got.KernelResponse.ErrorPackets)
	require.Zero(t, got.XSKRedirect.ErrorPackets)
	require.Zero(t, got.Errors.XDPPackets)
	require.Zero(t, got.Errors.XSKPackets)
}

func TestNewEventFromDataplaneMapsEventFields(t *testing.T) {
	observedAt := time.Unix(1710000000, 123).UTC()

	got := NewEventFromDataplane(model.EventRecord{
		ObservedAt: observedAt,
		RuleID:     1002,
		Action:     "tcp_reset",
		Verdict:    "xdp_tx",
		SIP:        "10.1.2.3",
		DIP:        "192.168.1.20",
		SPort:      52345,
		DPort:      80,
		IPProto:    6,
	})

	require.Equal(t, int64(1710000000), got.Timestamp)
	require.Equal(t, "rule_event", got.Type)
	require.Equal(t, uint32(1002), got.RuleID)
	require.Equal(t, "tcp_reset", got.Action)
	require.Equal(t, "xdp_tx", got.Verdict)
	require.Equal(t, uint32(0x0a010203), got.SIP)
	require.Equal(t, uint32(0xc0a80114), got.DIP)
	require.Equal(t, uint16(52345), got.SPort)
	require.Equal(t, uint16(80), got.DPort)
	require.Equal(t, uint8(6), got.IPProto)
	require.Empty(t, got.Path)
	require.Empty(t, got.Result)
	require.Zero(t, got.IfIndex)
}

func TestDataplaneRuntimeAdapterReadStatsPropagatesError(t *testing.T) {
	wantErr := errors.New("read dataplane stats")
	adapter := NewDataplaneRuntimeAdapter(staticDataplaneStatsReader{err: wantErr}, nil)

	_, err := adapter.ReadStats(context.Background())

	require.ErrorIs(t, err, wantErr)
}

func TestDataplaneRuntimeAdapterSubscribeEventsReturnsUnsupported(t *testing.T) {
	adapter := NewDataplaneRuntimeAdapter(staticDataplaneStatsReader{}, nil)

	events, err := adapter.SubscribeEvents(context.Background())

	require.Nil(t, events)
	require.ErrorIs(t, err, ErrEventStreamUnsupported)
}

func TestDataplaneRuntimeAdapterSubscribeEventsMapsRecords(t *testing.T) {
	observedAt := time.Unix(1710000000, 0).UTC()
	source := &staticDataplaneEventSubscriber{
		events: make(chan model.EventRecord, 1),
	}
	source.events <- model.EventRecord{
		ObservedAt: observedAt,
		RuleID:     1002,
		Action:     "tcp_reset",
		Verdict:    "xdp_tx",
		SIP:        "10.1.2.3",
		DIP:        "192.168.1.20",
		SPort:      52345,
		DPort:      80,
		IPProto:    6,
	}
	adapter := NewDataplaneRuntimeAdapter(staticDataplaneStatsReader{}, source)

	events, err := adapter.SubscribeEvents(context.Background())

	require.NoError(t, err)
	got := readAgentServiceEvent(t, events)
	require.Equal(t, int64(1710000000), got.Timestamp)
	require.Equal(t, "rule_event", got.Type)
	require.Equal(t, uint32(1002), got.RuleID)
	require.Equal(t, "tcp_reset", got.Action)
	require.Equal(t, "xdp_tx", got.Verdict)
	require.Equal(t, uint32(0x0a010203), got.SIP)
	require.Equal(t, uint32(0xc0a80114), got.DIP)
	require.Equal(t, uint16(52345), got.SPort)
	require.Equal(t, uint16(80), got.DPort)
	require.Equal(t, uint8(6), got.IPProto)
}

func TestDataplaneRuntimeAdapterSubscribeEventsPropagatesError(t *testing.T) {
	wantErr := errors.New("subscribe failed")
	source := &staticDataplaneEventSubscriber{err: wantErr}
	adapter := NewDataplaneRuntimeAdapter(staticDataplaneStatsReader{}, source)

	events, err := adapter.SubscribeEvents(context.Background())

	require.Nil(t, events)
	require.ErrorIs(t, err, wantErr)
}

func TestDataplaneRuntimeAdapterSubscribeEventsStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &staticDataplaneEventSubscriber{
		events: make(chan model.EventRecord),
	}
	adapter := NewDataplaneRuntimeAdapter(staticDataplaneStatsReader{}, source)
	events, err := adapter.SubscribeEvents(ctx)
	require.NoError(t, err)

	cancel()

	select {
	case _, ok := <-events:
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for mapped event stream to close")
	}
}

type staticDataplaneStatsReader struct {
	stats model.DataplaneStats
	err   error
}

func (r staticDataplaneStatsReader) ReadStats() (model.DataplaneStats, error) {
	if r.err != nil {
		return model.DataplaneStats{}, r.err
	}
	return r.stats, nil
}

type staticDataplaneEventSubscriber struct {
	events chan model.EventRecord
	err    error
}

func (s *staticDataplaneEventSubscriber) Events() []model.EventRecord {
	return nil
}

func (s *staticDataplaneEventSubscriber) SubscribeEvents(ctx context.Context) (<-chan model.EventRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.events, nil
}

func readAgentServiceEvent(t *testing.T, events <-chan types.Event) types.Event {
	t.Helper()

	select {
	case item := <-events:
		return item
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for agent event")
	}
	return types.Event{}
}
