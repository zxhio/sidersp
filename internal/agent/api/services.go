package api

import (
	"context"

	"sidersp/internal/agent/types"
)

type StatusService interface {
	Health(ctx context.Context) (types.Health, error)
	Status(ctx context.Context) (types.Status, error)
}
