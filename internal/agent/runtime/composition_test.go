package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/model"
)

func TestNewCompositionDefaultModeUsesInMemoryRuntime(t *testing.T) {
	composition, err := NewComposition(Options{})
	require.NoError(t, err)
	require.Equal(t, ModeInMemory, composition.Mode())
	requireServices(t, composition.Services)

	_, err = composition.Services.Attachments.CreateAttachment(context.Background(), types.Attachment{IfIndex: 3}, false)
	require.NoError(t, err)

	status, err := composition.Services.Status.Status(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, status.Attachments)
}

func TestNewCompositionDataplaneModeRequiresInterface(t *testing.T) {
	called := false
	composition, err := NewComposition(Options{Mode: ModeDataplane}, WithDataplaneOpener(func(dataplane.Options) (DataplaneRuntime, error) {
		called = true
		return nil, errors.New("should not open dataplane")
	}))

	require.Nil(t, composition)
	require.False(t, called)
	require.ErrorContains(t, err, "dataplane interface is required")
}

func TestNewCompositionDataplaneModeWiresStatsAdapter(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		stats: model.DataplaneStats{RXPackets: 42},
	}
	var opened dataplane.Options
	composition, err := NewComposition(Options{
		Mode: ModeDataplane,
		Dataplane: DataplaneOptions{
			Interface: "eth0",
		},
	}, WithDataplaneOpener(func(options dataplane.Options) (DataplaneRuntime, error) {
		opened = options
		return fakeRuntime, nil
	}))
	require.NoError(t, err)
	require.Equal(t, ModeDataplane, composition.Mode())
	requireServices(t, composition.Services)
	require.Equal(t, "eth0", opened.Interface)

	stats, err := composition.Services.Stats.Stats(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(42), stats.Ingress.Packets)

	events, err := composition.Services.Events.SubscribeEvents(context.Background())
	require.Nil(t, events)
	require.ErrorIs(t, err, service.ErrEventStreamUnsupported)

	require.NoError(t, composition.Close())
	require.True(t, fakeRuntime.closed)
}

func requireServices(t *testing.T, services Services) {
	t.Helper()
	require.NotNil(t, services.Status)
	require.NotNil(t, services.Ruleset)
	require.NotNil(t, services.Attachments)
	require.NotNil(t, services.Response)
	require.NotNil(t, services.Dispatch)
	require.NotNil(t, services.Stats)
	require.NotNil(t, services.Events)
}

type fakeDataplaneRuntime struct {
	stats  model.DataplaneStats
	events []model.EventRecord
	closed bool
}

func (r *fakeDataplaneRuntime) ReadStats() (model.DataplaneStats, error) {
	return r.stats, nil
}

func (r *fakeDataplaneRuntime) Events() []model.EventRecord {
	return r.events
}

func (r *fakeDataplaneRuntime) Close() error {
	r.closed = true
	return nil
}
