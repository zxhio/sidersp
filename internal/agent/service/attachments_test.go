package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
)

func TestAttachmentDryRunDoesNotModifyCurrentState(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewAttachmentService(runtime)

	got, err := svc.CreateAttachment(context.Background(), testAttachment(3), true)

	require.NoError(t, err)
	require.Equal(t, 3, got.IfIndex)
	require.True(t, got.Enabled)
	require.Equal(t, types.AttachModeNative, got.AttachMode)
	require.Equal(t, types.MissVerdictPass, got.MissVerdict)
	require.Equal(t, []int{0}, got.XSK.Queues)
	require.Zero(t, got.Runtime.ProgramID)

	items, err := svc.ListAttachments(context.Background())
	require.NoError(t, err)
	require.Empty(t, items)

	count, err := runtime.AttachmentCount(context.Background())
	require.NoError(t, err)
	require.Zero(t, count)
}

func TestAttachmentCreateRejectsDuplicateIfIndex(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewAttachmentService(runtime)
	_, err := svc.CreateAttachment(context.Background(), testAttachment(4), false)
	require.NoError(t, err)

	_, err = svc.CreateAttachment(context.Background(), testAttachment(4), false)

	require.ErrorAs(t, err, &types.ConflictError{})
	require.ErrorContains(t, err, "already exists")
}

func TestAttachmentSetEnabledOnlyChangesEnabled(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewAttachmentService(runtime)
	created, err := svc.CreateAttachment(context.Background(), types.Attachment{
		IfIndex:     5,
		IfName:      "eth5",
		AttachMode:  types.AttachModeGeneric,
		MissVerdict: types.MissVerdictDrop,
		Channels: types.AttachmentChannels{
			RXQueueCount:    2,
			MaxRXQueueCount: 4,
		},
		XSK: types.AttachmentXSK{
			Enabled: true,
			Queues:  []int{1},
		},
	}, false)
	require.NoError(t, err)

	got, err := svc.SetAttachmentEnabled(context.Background(), 5, false)

	require.NoError(t, err)
	require.False(t, got.Enabled)
	require.Equal(t, created.IfIndex, got.IfIndex)
	require.Equal(t, created.IfName, got.IfName)
	require.Equal(t, created.AttachMode, got.AttachMode)
	require.Equal(t, created.MissVerdict, got.MissVerdict)
	require.Equal(t, created.Channels, got.Channels)
	require.Equal(t, created.XSK, got.XSK)
	require.Zero(t, got.Runtime.ProgramID)
}

func TestAttachmentDeleteRemovesCurrentState(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewAttachmentService(runtime)
	_, err := svc.CreateAttachment(context.Background(), testAttachment(6), false)
	require.NoError(t, err)

	require.NoError(t, svc.DeleteAttachment(context.Background(), 6))

	items, err := svc.ListAttachments(context.Background())
	require.NoError(t, err)
	require.Empty(t, items)

	_, err = svc.GetAttachment(context.Background(), 6)
	require.ErrorAs(t, err, &types.NotFoundError{})
}

func TestAttachmentValidationRejectsInvalidQueues(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewAttachmentService(runtime)

	_, err := svc.CreateAttachment(context.Background(), types.Attachment{
		IfIndex: 7,
		Channels: types.AttachmentChannels{
			RXQueueCount: 2,
		},
		XSK: types.AttachmentXSK{
			Queues: []int{0, 2},
		},
	}, true)

	require.ErrorContains(t, err, "must be less than enabled rx queue count")
}

func testAttachment(ifindex int) types.Attachment {
	return types.Attachment{IfIndex: ifindex}
}
