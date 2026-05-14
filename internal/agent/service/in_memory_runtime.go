package service

import (
	"context"
	"sync"

	"sidersp/internal/agent/types"
)

type InMemoryRuntime struct {
	mu      sync.RWMutex
	ruleset types.Ruleset
}

func NewInMemoryRuntime() *InMemoryRuntime {
	return &InMemoryRuntime{}
}

func (r *InMemoryRuntime) RuntimeDeps() RuntimeDeps {
	return RuntimeDeps{
		Attachments: r,
		Ruleset:     r,
		Response:    r,
		Dispatch:    r,
	}
}

func (r *InMemoryRuntime) AttachmentCount(ctx context.Context) (int, error) {
	return 0, nil
}

func (r *InMemoryRuntime) RulesetVersion(ctx context.Context) (uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ruleset.Version, nil
}

func (r *InMemoryRuntime) GetRuleset(ctx context.Context) (types.Ruleset, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneRuleset(r.ruleset), nil
}

func (r *InMemoryRuntime) ValidateRuleset(ctx context.Context, ruleset types.Ruleset) error {
	return validateRuleset(ruleset)
}

func (r *InMemoryRuntime) ReplaceRuleset(ctx context.Context, ruleset types.Ruleset) (types.Ruleset, error) {
	if err := validateRuleset(ruleset); err != nil {
		return types.Ruleset{}, err
	}

	next := cloneRuleset(ruleset)
	r.mu.Lock()
	r.ruleset = next
	r.mu.Unlock()
	return cloneRuleset(next), nil
}

func (r *InMemoryRuntime) ClearRuleset(ctx context.Context) error {
	r.mu.Lock()
	r.ruleset = types.Ruleset{}
	r.mu.Unlock()
	return nil
}

func (r *InMemoryRuntime) ResponseConfigured(ctx context.Context) (bool, error) {
	return false, nil
}

func (r *InMemoryRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	return false, nil
}
