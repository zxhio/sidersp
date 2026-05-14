package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type StatsService struct {
	runtime StatsRuntime
}

func NewStatsService(runtime StatsRuntime) *StatsService {
	if runtime == nil {
		panic("agent service: stats runtime is required")
	}
	return &StatsService{runtime: runtime}
}

func (s *StatsService) Stats(ctx context.Context) (types.Stats, error) {
	return s.runtime.ReadStats(ctx)
}
