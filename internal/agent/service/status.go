package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type StatusService struct{}

func NewStatusService() *StatusService {
	return &StatusService{}
}

func (s *StatusService) Health(ctx context.Context) (types.Health, error) {
	return types.Health{Status: types.HealthStatusOK}, nil
}

func (s *StatusService) Status(ctx context.Context) (types.Status, error) {
	return types.Status{
		Status:             types.StatusRunning,
		Attachments:        0,
		RulesetVersion:     0,
		ResponseConfigured: false,
		DispatchEnabled:    false,
	}, nil
}
