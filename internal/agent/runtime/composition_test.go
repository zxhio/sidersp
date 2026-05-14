package runtime

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/model"
	"sidersp/internal/rule"
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

func TestNewCompositionDataplaneModeOpensFromAttachment(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID: 101,
		stats:     model.DataplaneStats{RXPackets: 42},
	}
	var opened []dataplane.Options
	composition, err := NewComposition(Options{
		Mode: ModeDataplane,
	}, WithDataplaneOpener(func(options dataplane.Options) (DataplaneRuntime, error) {
		opened = append(opened, options)
		return fakeRuntime, nil
	}), WithInterfaceLookup(fakeInterfaceByIndex))
	require.NoError(t, err)
	require.Equal(t, ModeDataplane, composition.Mode())
	requireServices(t, composition.Services)
	require.Empty(t, opened)

	attachment, err := composition.Services.Attachments.CreateAttachment(context.Background(), types.Attachment{IfIndex: 3}, false)
	require.NoError(t, err)
	require.True(t, attachment.Enabled)
	require.Equal(t, uint32(101), attachment.Runtime.ProgramID)
	require.Len(t, opened, 1)
	require.Equal(t, "eth3", opened[0].Interface)
	require.True(t, fakeRuntime.attached)

	stats, err := composition.Services.Stats.Stats(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(42), stats.Ingress.Packets)

	events, err := composition.Services.Events.SubscribeEvents(context.Background())
	require.Nil(t, events)
	require.ErrorIs(t, err, service.ErrEventStreamUnsupported)

	require.NoError(t, composition.Close())
	require.True(t, fakeRuntime.closed)
}

func fakeInterfaceByIndex(index int) (*net.Interface, error) {
	return &net.Interface{Index: index, Name: "eth" + strconv.Itoa(index)}, nil
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
	programID    uint32
	stats        model.DataplaneStats
	events       []model.EventRecord
	appliedRules []rule.RuleSet
	appliedXDP   []dataplane.XDPResponseOptions
	attached     bool
	closed       bool
	applyErr     error
	xdpErr       error
	closeErr     error
}

func (r *fakeDataplaneRuntime) ReadStats() (model.DataplaneStats, error) {
	return r.stats, nil
}

func (r *fakeDataplaneRuntime) Events() []model.EventRecord {
	return r.events
}

func (r *fakeDataplaneRuntime) Attach() error {
	r.attached = true
	return nil
}

func (r *fakeDataplaneRuntime) ProgramID() (uint32, error) {
	return r.programID, nil
}

func (r *fakeDataplaneRuntime) ReplaceRules(set rule.RuleSet) error {
	r.appliedRules = append(r.appliedRules, cloneRuleSet(set))
	if r.applyErr != nil {
		return r.applyErr
	}
	return nil
}

func (r *fakeDataplaneRuntime) ReplaceXDPResponse(options dataplane.XDPResponseOptions) error {
	r.appliedXDP = append(r.appliedXDP, options)
	if r.xdpErr != nil {
		return r.xdpErr
	}
	return nil
}

func (r *fakeDataplaneRuntime) Close() error {
	r.closed = true
	return r.closeErr
}
