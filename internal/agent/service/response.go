package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type ResponseService struct {
	runtime ResponseConfigRuntime
}

func NewResponseService(runtime ResponseConfigRuntime) *ResponseService {
	if runtime == nil {
		panic("agent service: response runtime is required")
	}
	return &ResponseService{runtime: runtime}
}

func (s *ResponseService) GetResponse(ctx context.Context) (types.ResponseConfig, error) {
	return s.runtime.GetResponse(ctx)
}

func (s *ResponseService) ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error) {
	return s.runtime.ReplaceResponse(ctx, config)
}

func (s *ResponseService) ClearResponse(ctx context.Context) error {
	return s.runtime.ClearResponse(ctx)
}

func defaultResponseConfig() types.ResponseConfig {
	return types.ResponseConfig{VLANMode: types.VLANModePreserve}
}

func normalizeResponseConfig(config types.ResponseConfig) (types.ResponseConfig, error) {
	if config.IfIndex <= 0 {
		return types.ResponseConfig{}, types.NewValidationError("ifindex must be greater than 0")
	}
	if config.VLANMode == "" {
		config.VLANMode = types.VLANModePreserve
	}
	if err := validateVLANMode(config.VLANMode); err != nil {
		return types.ResponseConfig{}, err
	}
	return config, nil
}

func validateVLANMode(value string) error {
	switch value {
	case types.VLANModePreserve, types.VLANModeAccess:
		return nil
	default:
		return types.NewValidationError("vlan_mode must be preserve or access")
	}
}
