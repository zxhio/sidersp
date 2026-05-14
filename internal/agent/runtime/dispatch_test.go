package runtime

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
)

func TestDataplaneDispatchReplaceAppliesAndStoresConfig(t *testing.T) {
	applier := &recordingDispatchApplier{}
	runtime := newTestDataplaneAttachmentRuntime(&recordingDataplaneOpener{})
	runtime.dispatchApplier = applier
	svc := service.NewDispatchService(runtime)

	got, err := svc.ReplaceDispatch(context.Background(), testDispatchConfig(30, types.VLANModeAccess))

	require.NoError(t, err)
	require.True(t, got.Enabled)
	require.Equal(t, types.DispatchBackendAFPacket, got.Backend)
	require.Equal(t, 30, got.TargetIfIndex)
	require.Equal(t, "eth30", got.TargetIfName)
	require.Equal(t, types.VLANModeAccess, got.VLANMode)
	require.Equal(t, 1024, got.QueueSize)
	require.Equal(t, 512, got.MaxPacketBytes)
	require.Equal(t, []types.DispatchConfig{got}, applier.configs)

	stored, err := runtime.GetDispatch(context.Background())
	require.NoError(t, err)
	require.Equal(t, got, stored)
	enabled, err := runtime.DispatchEnabled(context.Background())
	require.NoError(t, err)
	require.True(t, enabled)
}

func TestDataplaneDispatchApplyFailureDoesNotStoreConfig(t *testing.T) {
	applier := &recordingDispatchApplier{}
	runtime := newTestDataplaneAttachmentRuntime(&recordingDataplaneOpener{})
	runtime.dispatchApplier = applier
	svc := service.NewDispatchService(runtime)
	previous := testDispatchConfig(40, types.VLANModePreserve)
	previous, err := svc.ReplaceDispatch(context.Background(), previous)
	require.NoError(t, err)
	applier.err = errors.New("apply failed")

	_, err = svc.ReplaceDispatch(context.Background(), testDispatchConfig(41, types.VLANModeAccess))

	require.ErrorContains(t, err, "apply failed")
	stored, getErr := runtime.GetDispatch(context.Background())
	require.NoError(t, getErr)
	require.Equal(t, previous, stored)
	require.Len(t, applier.configs, 2)
	require.Equal(t, 41, applier.configs[1].TargetIfIndex)
}

func TestDataplaneDispatchClearAppliesDefaultDisabledConfig(t *testing.T) {
	applier := &recordingDispatchApplier{}
	runtime := newTestDataplaneAttachmentRuntime(&recordingDataplaneOpener{})
	runtime.dispatchApplier = applier
	svc := service.NewDispatchService(runtime)
	_, err := svc.ReplaceDispatch(context.Background(), testDispatchConfig(50, types.VLANModeAccess))
	require.NoError(t, err)

	err = svc.ClearDispatch(context.Background())

	require.NoError(t, err)
	require.Len(t, applier.configs, 2)
	require.False(t, applier.configs[1].Enabled)
	require.Equal(t, types.DispatchBackendAFPacket, applier.configs[1].Backend)
	require.Equal(t, types.VLANModePreserve, applier.configs[1].VLANMode)
	require.Equal(t, defaultDataplaneDispatchQueueSize, applier.configs[1].QueueSize)
	require.Zero(t, applier.configs[1].TargetIfIndex)

	stored, err := runtime.GetDispatch(context.Background())
	require.NoError(t, err)
	require.False(t, stored.Enabled)
	require.Equal(t, types.DispatchBackendAFPacket, stored.Backend)
	require.Equal(t, types.VLANModePreserve, stored.VLANMode)
	enabled, err := runtime.DispatchEnabled(context.Background())
	require.NoError(t, err)
	require.False(t, enabled)
}

func testDispatchConfig(ifindex int, vlanMode string) types.DispatchConfig {
	return types.DispatchConfig{
		Enabled:        true,
		TargetIfIndex:  ifindex,
		TargetIfName:   "eth" + strconv.Itoa(ifindex),
		VLANMode:       vlanMode,
		QueueSize:      1024,
		MaxPacketBytes: 512,
	}
}

type recordingDispatchApplier struct {
	configs []types.DispatchConfig
	err     error
}

func (a *recordingDispatchApplier) ApplyDispatch(ctx context.Context, config types.DispatchConfig) error {
	a.configs = append(a.configs, cloneDispatchConfig(config))
	return a.err
}
