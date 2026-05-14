package runtime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/model"
)

func TestDataplaneAttachmentDryRunDoesNotOpen(t *testing.T) {
	opener := &recordingDataplaneOpener{}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.ValidateAttachment(context.Background(), types.Attachment{IfIndex: 3})

	require.NoError(t, err)
	require.Equal(t, 3, got.IfIndex)
	require.Equal(t, "eth3", got.IfName)
	require.True(t, got.Enabled)
	require.Empty(t, opener.opens)

	items, err := runtime.ListAttachments(context.Background())
	require.NoError(t, err)
	require.Empty(t, items)
}

func TestDataplaneAttachmentCreateOpensAndStoresState(t *testing.T) {
	opener := &recordingDataplaneOpener{
		next: []*fakeDataplaneRuntime{{programID: 101}},
	}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	got, err := runtime.CreateAttachment(context.Background(), types.Attachment{
		IfIndex:     3,
		AttachMode:  types.AttachModeGeneric,
		MissVerdict: types.MissVerdictDrop,
	})

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, "eth3", got.IfName)
	require.Equal(t, uint32(101), got.Runtime.ProgramID)
	require.Len(t, opener.opens, 1)
	require.Equal(t, "eth3", opener.opens[0].Interface)
	require.Equal(t, types.AttachModeGeneric, opener.opens[0].AttachMode)
	require.Equal(t, types.MissVerdictDrop, opener.opens[0].IngressVerdict)
	require.True(t, opener.runtimes[0].attached)

	stored, err := runtime.GetAttachment(context.Background(), 3)
	require.NoError(t, err)
	require.Equal(t, got, stored)
}

func TestDataplaneAttachmentOpenFailureDoesNotStoreState(t *testing.T) {
	opener := &recordingDataplaneOpener{err: errors.New("open failed")}
	runtime := newTestDataplaneAttachmentRuntime(opener)

	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 4})

	require.ErrorContains(t, err, "open failed")
	items, listErr := runtime.ListAttachments(context.Background())
	require.NoError(t, listErr)
	require.Empty(t, items)
	require.Len(t, opener.opens, 1)
}

func TestDataplaneAttachmentDuplicateDoesNotOpenAgain(t *testing.T) {
	opener := &recordingDataplaneOpener{
		next: []*fakeDataplaneRuntime{{programID: 101}},
	}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 5})
	require.NoError(t, err)

	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 5})

	require.ErrorAs(t, err, &types.ConflictError{})
	require.Len(t, opener.opens, 1)
}

func TestDataplaneAttachmentDisableClosesRuntimeAndKeepsAttachment(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 6})
	require.NoError(t, err)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 6, false)

	require.NoError(t, err)
	require.False(t, got.Enabled)
	require.Zero(t, got.Runtime.ProgramID)
	require.True(t, fakeRuntime.closed)

	stored, err := runtime.GetAttachment(context.Background(), 6)
	require.NoError(t, err)
	require.Equal(t, got, stored)
}

func TestDataplaneAttachmentReenableOpensRuntimeAgain(t *testing.T) {
	first := &fakeDataplaneRuntime{programID: 101}
	second := &fakeDataplaneRuntime{programID: 202}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{first, second}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 7})
	require.NoError(t, err)
	_, err = runtime.SetAttachmentEnabled(context.Background(), 7, false)
	require.NoError(t, err)

	got, err := runtime.SetAttachmentEnabled(context.Background(), 7, true)

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, uint32(202), got.Runtime.ProgramID)
	require.True(t, first.closed)
	require.True(t, second.attached)
	require.Len(t, opener.opens, 2)
}

func TestDataplaneAttachmentDeleteClosesRuntimeAndRemovesAttachment(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{programID: 101}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 8})
	require.NoError(t, err)

	err = runtime.DeleteAttachment(context.Background(), 8)

	require.NoError(t, err)
	require.True(t, fakeRuntime.closed)
	_, err = runtime.GetAttachment(context.Background(), 8)
	require.ErrorAs(t, err, &types.NotFoundError{})
}

func TestDataplaneAttachmentCloseFailureReturnsErrorAndKeepsAttachmentEnabled(t *testing.T) {
	fakeRuntime := &fakeDataplaneRuntime{
		programID: 101,
		closeErr:  errors.New("close failed"),
	}
	opener := &recordingDataplaneOpener{next: []*fakeDataplaneRuntime{fakeRuntime}}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 9})
	require.NoError(t, err)

	_, err = runtime.SetAttachmentEnabled(context.Background(), 9, false)

	require.ErrorContains(t, err, "close failed")
	stored, getErr := runtime.GetAttachment(context.Background(), 9)
	require.NoError(t, getErr)
	require.True(t, stored.Enabled)
	require.Equal(t, uint32(101), stored.Runtime.ProgramID)
}

func TestDataplaneAttachmentReadStatsAggregatesActiveRuntimes(t *testing.T) {
	opener := &recordingDataplaneOpener{
		next: []*fakeDataplaneRuntime{
			{programID: 101, stats: model.DataplaneStats{RXPackets: 10, ParseFailed: 1}},
			{programID: 202, stats: model.DataplaneStats{RXPackets: 20, TXFailed: 2}},
		},
	}
	runtime := newTestDataplaneAttachmentRuntime(opener)
	_, err := runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 10})
	require.NoError(t, err)
	_, err = runtime.CreateAttachment(context.Background(), types.Attachment{IfIndex: 11})
	require.NoError(t, err)

	got, err := runtime.ReadStats(context.Background())

	require.NoError(t, err)
	require.Equal(t, uint64(30), got.Ingress.Packets)
	require.Equal(t, uint64(3), got.Errors.XDPPackets)
}

func newTestDataplaneAttachmentRuntime(opener *recordingDataplaneOpener) *DataplaneAttachmentRuntime {
	return NewDataplaneAttachmentRuntime(service.NewInMemoryRuntime(), opener.open, func(index int) (*net.Interface, error) {
		return &net.Interface{Index: index, Name: "eth" + strconv.Itoa(index)}, nil
	})
}

type recordingDataplaneOpener struct {
	opens    []dataplane.Options
	next     []*fakeDataplaneRuntime
	runtimes []*fakeDataplaneRuntime
	err      error
}

func (o *recordingDataplaneOpener) open(options dataplane.Options) (DataplaneRuntime, error) {
	o.opens = append(o.opens, options)
	if o.err != nil {
		return nil, o.err
	}
	if len(o.next) == 0 {
		runtime := &fakeDataplaneRuntime{}
		o.runtimes = append(o.runtimes, runtime)
		return runtime, nil
	}
	next := o.next[0]
	o.next = o.next[1:]
	o.runtimes = append(o.runtimes, next)
	return next, nil
}
