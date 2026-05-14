package service

import (
	"context"

	"sidersp/internal/agent/types"
)

func NewStatusService() *StatusService {
	return NewStatusServiceWithRuntime(NewNoopRuntimeDeps())
}

type StatusService struct {
	runtime RuntimeDeps
}

func NewStatusServiceWithRuntime(runtime RuntimeDeps) *StatusService {
	if runtime.Attachments == nil {
		panic("agent service: attachment runtime is required")
	}
	if runtime.Ruleset == nil {
		panic("agent service: ruleset runtime is required")
	}
	if runtime.Response == nil {
		panic("agent service: response runtime is required")
	}
	if runtime.Dispatch == nil {
		panic("agent service: dispatch runtime is required")
	}
	return &StatusService{runtime: runtime}
}

func (s *StatusService) Health(ctx context.Context) (types.Health, error) {
	return types.Health{Status: types.HealthStatusOK}, nil
}

func (s *StatusService) Status(ctx context.Context) (types.Status, error) {
	attachments, err := s.runtime.Attachments.AttachmentCount(ctx)
	if err != nil {
		return types.Status{}, err
	}
	rulesetVersion, err := s.runtime.Ruleset.RulesetVersion(ctx)
	if err != nil {
		return types.Status{}, err
	}
	responseConfigured, err := s.runtime.Response.ResponseConfigured(ctx)
	if err != nil {
		return types.Status{}, err
	}
	dispatchEnabled, err := s.runtime.Dispatch.DispatchEnabled(ctx)
	if err != nil {
		return types.Status{}, err
	}

	return types.Status{
		Status:             types.StatusRunning,
		Attachments:        attachments,
		RulesetVersion:     rulesetVersion,
		ResponseConfigured: responseConfigured,
		DispatchEnabled:    dispatchEnabled,
	}, nil
}
