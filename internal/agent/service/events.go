package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type EventService struct {
	runtime EventRuntime
}

func NewEventService(runtime EventRuntime) *EventService {
	if runtime == nil {
		panic("agent service: event runtime is required")
	}
	return &EventService{runtime: runtime}
}

func (s *EventService) SubscribeEvents(ctx context.Context) (<-chan types.Event, error) {
	return s.runtime.SubscribeEvents(ctx)
}
