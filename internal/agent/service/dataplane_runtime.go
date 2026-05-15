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
	return NewStatsFromRuntime(model.RuntimeStats{Dataplane: stats})
}

func NewStatsFromRuntime(stats model.RuntimeStats) types.Stats {
	dataplaneStats := stats.Dataplane
	responseStats := stats.Response
	return types.Stats{
		Ingress: types.IngressStats{
			Packets: dataplaneStats.RXPackets,
		},
		Parse: types.ParseStats{
			OKPackets:    dataplaneStats.ParseOKPackets,
			ErrorPackets: dataplaneStats.ParseFailed,
		},
		Match: types.MatchStats{
			HitPackets:  dataplaneStats.MatchedRules,
			MissPackets: dataplaneStats.MatchMissPackets,
		},
		KernelResponse: types.KernelResponseStats{
			Packets:         dataplaneStats.KernelResponsePackets,
			XDPTXPackets:    dataplaneStats.XDPTX,
			RedirectPackets: dataplaneStats.RedirectTX,
			ErrorPackets:    dataplaneStats.TXFailed,
		},
		XSKRedirect: types.XSKRedirectStats{
			Packets:      dataplaneStats.XskRedirected,
			ErrorPackets: dataplaneStats.XskRedirectFailed,
		},
		UserspaceResponse: types.UserspaceResponseStats{
			XSKRXPackets:      responseStats.XSKRXPackets,
			Packets:           responseStats.ResponseSent,
			XSKTXPackets:      responseStats.AFXDPTX,
			AFPacketTXPackets: responseStats.AFPacketTX,
			ErrorPackets:      responseStats.ResponseFailed,
		},
		Errors: types.ErrorStats{
			XDPPackets: dataplaneStats.ParseFailed +
				dataplaneStats.TXFailed +
				dataplaneStats.XskRedirectFailed +
				dataplaneStats.RingbufDropped,
			XSKPackets: responseStats.ResponseFailed,
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
