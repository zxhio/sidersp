package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type NoopRuntime struct{}

func (NoopRuntime) AttachmentCount(ctx context.Context) (int, error) {
	return 0, nil
}

func (NoopRuntime) RulesetVersion(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (NoopRuntime) GetRuleset(ctx context.Context) (types.Ruleset, error) {
	return types.Ruleset{}, nil
}

func (NoopRuntime) ValidateRuleset(ctx context.Context, ruleset types.Ruleset) error {
	return validateRuleset(ruleset)
}

func (NoopRuntime) ReplaceRuleset(ctx context.Context, ruleset types.Ruleset) (types.Ruleset, error) {
	if err := validateRuleset(ruleset); err != nil {
		return types.Ruleset{}, err
	}
	return cloneRuleset(ruleset), nil
}

func (NoopRuntime) ClearRuleset(ctx context.Context) error {
	return nil
}

func (NoopRuntime) ResponseConfigured(ctx context.Context) (bool, error) {
	return false, nil
}

func (NoopRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	return false, nil
}
