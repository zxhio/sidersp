package service

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"

	"sidersp/internal/agent/types"
	"sidersp/internal/model"
)

var ErrEventStreamUnsupported = errors.New("agent service: dataplane event streaming is not supported")

type DataplaneStatsReader interface {
	ReadStats() (model.DataplaneStats, error)
}

type DataplaneEventSource interface {
	Events() []model.EventRecord
}

type DataplaneEventSubscriber interface {
	SubscribeEvents(ctx context.Context) (<-chan model.EventRecord, error)
}

type DataplaneRuntimeAdapter struct {
	stats      DataplaneStatsReader
	events     DataplaneEventSource
	subscriber DataplaneEventSubscriber
}

func NewDataplaneRuntimeAdapter(stats DataplaneStatsReader, events DataplaneEventSource) *DataplaneRuntimeAdapter {
	if stats == nil {
		panic("agent service: dataplane stats reader is required")
	}
	return &DataplaneRuntimeAdapter{
		stats:      stats,
		events:     events,
		subscriber: eventSubscriber(events),
	}
}

func (a *DataplaneRuntimeAdapter) ReadStats(ctx context.Context) (types.Stats, error) {
	stats, err := a.stats.ReadStats()
	if err != nil {
		return types.Stats{}, err
	}
	return NewStatsFromDataplane(stats), nil
}

func (a *DataplaneRuntimeAdapter) SubscribeEvents(ctx context.Context) (<-chan types.Event, error) {
	if a.subscriber == nil {
		return nil, ErrEventStreamUnsupported
	}
	events, err := a.subscriber.SubscribeEvents(ctx)
	if err != nil {
		return nil, err
	}
	return mapDataplaneEvents(ctx, events), nil
}

func NewStatsFromDataplane(stats model.DataplaneStats) types.Stats {
	return types.Stats{
		Ingress: types.IngressStats{
			Packets: stats.RXPackets,
		},
		Parse: types.ParseStats{
			ErrorPackets: stats.ParseFailed,
		},
		Match: types.MatchStats{
			HitPackets: stats.MatchedRules,
		},
		KernelResponse: types.KernelResponseStats{
			XDPTXPackets:    stats.XDPTX,
			RedirectPackets: stats.RedirectTX,
			ErrorPackets:    stats.TXFailed,
		},
		XSKRedirect: types.XSKRedirectStats{
			Packets:      stats.XskRedirected,
			ErrorPackets: stats.XskRedirectFailed,
		},
		Errors: types.ErrorStats{
			XDPPackets: stats.ParseFailed +
				stats.TXFailed +
				stats.XskRedirectFailed +
				stats.RingbufDropped,
		},
	}
}

func NewEventFromDataplane(item model.EventRecord) types.Event {
	return types.Event{
		Timestamp: item.ObservedAt.Unix(),
		Type:      "rule_event",
		RuleID:    item.RuleID,
		Action:    item.Action,
		Verdict:   item.Verdict,
		SIP:       ipv4ToUint32(item.SIP),
		DIP:       ipv4ToUint32(item.DIP),
		SPort:     item.SPort,
		DPort:     item.DPort,
		IPProto:   item.IPProto,
	}
}

func ipv4ToUint32(raw string) uint32 {
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return 0
	}
	v4 := addr.As4()
	return binary.BigEndian.Uint32(v4[:])
}

func eventSubscriber(events DataplaneEventSource) DataplaneEventSubscriber {
	subscriber, ok := events.(DataplaneEventSubscriber)
	if !ok {
		return nil
	}
	return subscriber
}

func mapDataplaneEvents(ctx context.Context, events <-chan model.EventRecord) <-chan types.Event {
	out := make(chan types.Event, 64)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case item, ok := <-events:
				if !ok {
					return
				}
				next := NewEventFromDataplane(item)
				select {
				case out <- next:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}
