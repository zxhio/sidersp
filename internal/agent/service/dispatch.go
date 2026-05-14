package service

import (
	"context"

	"sidersp/internal/agent/types"
)

const defaultDispatchQueueSize = 4096

type DispatchService struct {
	runtime DispatchConfigRuntime
}

func NewDispatchService(runtime DispatchConfigRuntime) *DispatchService {
	if runtime == nil {
		panic("agent service: dispatch runtime is required")
	}
	return &DispatchService{runtime: runtime}
}

func (s *DispatchService) GetDispatch(ctx context.Context) (types.DispatchConfig, error) {
	return s.runtime.GetDispatch(ctx)
}

func (s *DispatchService) ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error) {
	return s.runtime.ReplaceDispatch(ctx, config)
}

func (s *DispatchService) ClearDispatch(ctx context.Context) error {
	return s.runtime.ClearDispatch(ctx)
}

func defaultDispatchConfig() types.DispatchConfig {
	return types.DispatchConfig{
		Backend:        types.DispatchBackendAFPacket,
		VLANMode:       types.VLANModePreserve,
		QueueSize:      defaultDispatchQueueSize,
		MaxPacketBytes: 0,
	}
}

func normalizeDispatchConfig(config types.DispatchConfig) (types.DispatchConfig, error) {
	if config.Backend == "" {
		config.Backend = types.DispatchBackendAFPacket
	}
	if config.Backend != types.DispatchBackendAFPacket {
		return types.DispatchConfig{}, types.NewValidationError("backend must be af_packet")
	}
	if config.VLANMode == "" {
		config.VLANMode = types.VLANModePreserve
	}
	if err := validateVLANMode(config.VLANMode); err != nil {
		return types.DispatchConfig{}, err
	}
	if config.QueueSize == 0 {
		config.QueueSize = defaultDispatchQueueSize
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
	return config, nil
}
