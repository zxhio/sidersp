package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
)

func TestStatsServiceReturnsRuntimeSnapshot(t *testing.T) {
	runtime := staticStatsRuntime{
		stats: types.Stats{
			Ingress: types.IngressStats{Packets: 10},
			Parse: types.ParseStats{
				OKPackets:    9,
				ErrorPackets: 1,
			},
			Dispatch: types.DispatchStats{
				Packets:       3,
				QueuedPackets: 2,
			},
		},
	}
	svc := NewStatsService(runtime)

	got, err := svc.Stats(context.Background())

	require.NoError(t, err)
	require.Equal(t, runtime.stats, got)
}

func TestStatsServiceReturnsRuntimeError(t *testing.T) {
	wantErr := errors.New("read stats failed")
	svc := NewStatsService(staticStatsRuntime{err: wantErr})

	_, err := svc.Stats(context.Background())

	require.ErrorIs(t, err, wantErr)
}

type staticStatsRuntime struct {
	stats types.Stats
	err   error
}

func (r staticStatsRuntime) ReadStats(ctx context.Context) (types.Stats, error) {
	if r.err != nil {
		return types.Stats{}, r.err
	}
	return r.stats, nil
}
