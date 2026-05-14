package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
)

func TestResponseReplaceUpdatesCurrentConfig(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewResponseService(runtime)

	got, err := svc.ReplaceResponse(context.Background(), types.ResponseConfig{
		IfIndex:  3,
		IfName:   "eth1",
		VLANMode: types.VLANModeAccess,
	})

	require.NoError(t, err)
	require.Equal(t, 3, got.IfIndex)
	require.Equal(t, "eth1", got.IfName)
	require.Equal(t, types.VLANModeAccess, got.VLANMode)

	configured, err := runtime.ResponseConfigured(context.Background())
	require.NoError(t, err)
	require.True(t, configured)
}

func TestResponseClearRestoresDefaultConfig(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewResponseService(runtime)
	_, err := svc.ReplaceResponse(context.Background(), types.ResponseConfig{IfIndex: 4})
	require.NoError(t, err)

	require.NoError(t, svc.ClearResponse(context.Background()))

	got, err := svc.GetResponse(context.Background())
	require.NoError(t, err)
	require.Zero(t, got.IfIndex)
	require.Equal(t, types.VLANModePreserve, got.VLANMode)

	configured, err := runtime.ResponseConfigured(context.Background())
	require.NoError(t, err)
	require.False(t, configured)
}

func TestResponseRejectsInvalidConfig(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewResponseService(runtime)

	_, err := svc.ReplaceResponse(context.Background(), types.ResponseConfig{IfIndex: 0})

	require.ErrorContains(t, err, "ifindex must be greater than 0")
}

func TestDispatchReplaceUpdatesCurrentConfig(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewDispatchService(runtime)

	got, err := svc.ReplaceDispatch(context.Background(), types.DispatchConfig{
		Enabled:        true,
		TargetIfIndex:  5,
		TargetIfName:   "eth2",
		VLANMode:       types.VLANModeAccess,
		QueueSize:      2048,
		MaxPacketBytes: 512,
	})

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, types.DispatchBackendAFPacket, got.Backend)
	require.Equal(t, 5, got.TargetIfIndex)
	require.Equal(t, "eth2", got.TargetIfName)
	require.Equal(t, types.VLANModeAccess, got.VLANMode)
	require.Equal(t, 2048, got.QueueSize)
	require.Equal(t, 512, got.MaxPacketBytes)

	enabled, err := runtime.DispatchEnabled(context.Background())
	require.NoError(t, err)
	require.True(t, enabled)
}

func TestDispatchClearRestoresDefaultConfig(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewDispatchService(runtime)
	_, err := svc.ReplaceDispatch(context.Background(), types.DispatchConfig{
		Enabled:       true,
		TargetIfIndex: 6,
	})
	require.NoError(t, err)

	require.NoError(t, svc.ClearDispatch(context.Background()))

	got, err := svc.GetDispatch(context.Background())
	require.NoError(t, err)
	require.False(t, got.Enabled)
	require.Equal(t, types.DispatchBackendAFPacket, got.Backend)
	require.Equal(t, types.VLANModePreserve, got.VLANMode)
	require.Equal(t, defaultDispatchQueueSize, got.QueueSize)
	require.Zero(t, got.MaxPacketBytes)

	enabled, err := runtime.DispatchEnabled(context.Background())
	require.NoError(t, err)
	require.False(t, enabled)
}

func TestDispatchRejectsInvalidConfig(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewDispatchService(runtime)

	_, err := svc.ReplaceDispatch(context.Background(), types.DispatchConfig{
		Enabled: true,
	})

	require.ErrorContains(t, err, "target_ifindex must be greater than 0")
}
