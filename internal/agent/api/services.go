package api

import (
	"context"

	"sidersp/internal/agent/types"
)

type StatusService interface {
	Health(ctx context.Context) (types.Health, error)
	Status(ctx context.Context) (types.Status, error)
}

type RulesetService interface {
	GetRuleset(ctx context.Context) (types.Ruleset, error)
	ReplaceRuleset(ctx context.Context, ruleset types.Ruleset, dryRun bool) (types.Ruleset, error)
	ClearRuleset(ctx context.Context) error
}
