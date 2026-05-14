package runtime

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/types"
)

const defaultDataplaneDispatchQueueSize = 4096

type dispatchState struct {
	config     types.DispatchConfig
	configured bool
}

type dispatchApplier interface {
	ApplyDispatch(ctx context.Context, config types.DispatchConfig) error
}

type noopDispatchApplier struct{}

func (noopDispatchApplier) ApplyDispatch(ctx context.Context, config types.DispatchConfig) error {
	return nil
}

func (r *DataplaneAttachmentRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.dispatch.configured {
		return false, nil
	}
	return r.dispatch.config.Enabled, nil
}

func (r *DataplaneAttachmentRuntime) GetDispatch(ctx context.Context) (types.DispatchConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return currentDispatchConfig(r.dispatch), nil
}

func (r *DataplaneAttachmentRuntime) ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error) {
	next, err := normalizeDataplaneDispatchConfig(config)
	if err != nil {
		return types.DispatchConfig{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.dispatchApplier.ApplyDispatch(ctx, next); err != nil {
		return types.DispatchConfig{}, fmt.Errorf("apply dispatch config: %w", err)
	}

	r.dispatch = dispatchState{
		config:     cloneDispatchConfig(next),
		configured: true,
	}
	logrus.WithFields(logrus.Fields{
		"enabled":        next.Enabled,
		"backend":        next.Backend,
		"target_ifindex": next.TargetIfIndex,
		"vlan_mode":      next.VLANMode,
		"queue_size":     next.QueueSize,
	}).Info("Applied dataplane dispatch config")
	return cloneDispatchConfig(next), nil
}

func (r *DataplaneAttachmentRuntime) ClearDispatch(ctx context.Context) error {
	next := defaultDataplaneDispatchConfig()

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.dispatchApplier.ApplyDispatch(ctx, next); err != nil {
		return fmt.Errorf("clear dispatch config: %w", err)
	}

	r.dispatch = dispatchState{}
	logrus.Info("Cleared dataplane dispatch config")
	return nil
}

func normalizeDataplaneDispatchConfig(config types.DispatchConfig) (types.DispatchConfig, error) {
	if config.Backend == "" {
		config.Backend = types.DispatchBackendAFPacket
	}
	if config.Backend != types.DispatchBackendAFPacket {
		return types.DispatchConfig{}, types.NewValidationError("backend must be af_packet")
	}
	if config.VLANMode == "" {
		config.VLANMode = types.VLANModePreserve
	}
	switch config.VLANMode {
	case types.VLANModePreserve, types.VLANModeAccess:
	default:
		return types.DispatchConfig{}, types.NewValidationError("vlan_mode must be preserve or access")
	}
	if config.QueueSize == 0 {
		config.QueueSize = defaultDataplaneDispatchQueueSize
	}
	if config.QueueSize < 0 {
		return types.DispatchConfig{}, types.NewValidationError("queue_size must be greater than 0")
	}
	if config.MaxPacketBytes < 0 {
		return types.DispatchConfig{}, types.NewValidationError("max_packet_bytes must be greater than or equal to 0")
	}
	if config.Enabled && config.TargetIfIndex <= 0 {
		return types.DispatchConfig{}, types.NewValidationError("target_ifindex must be greater than 0 when dispatch is enabled")
	}
	return cloneDispatchConfig(config), nil
}

func currentDispatchConfig(state dispatchState) types.DispatchConfig {
	if !state.configured {
		return defaultDataplaneDispatchConfig()
	}
	return cloneDispatchConfig(state.config)
}

func defaultDataplaneDispatchConfig() types.DispatchConfig {
	return types.DispatchConfig{
		Backend:        types.DispatchBackendAFPacket,
		VLANMode:       types.VLANModePreserve,
		QueueSize:      defaultDataplaneDispatchQueueSize,
		MaxPacketBytes: 0,
	}
}

func cloneDispatchConfig(config types.DispatchConfig) types.DispatchConfig {
	return types.DispatchConfig{
		Enabled:        config.Enabled,
		Backend:        config.Backend,
		TargetIfIndex:  config.TargetIfIndex,
		TargetIfName:   config.TargetIfName,
		VLANMode:       config.VLANMode,
		QueueSize:      config.QueueSize,
		MaxPacketBytes: config.MaxPacketBytes,
	}
}
