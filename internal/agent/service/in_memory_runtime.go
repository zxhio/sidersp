package service

import (
	"context"
	"sync"

	"sidersp/internal/agent/types"
)

type InMemoryRuntime struct {
	mu                 sync.RWMutex
	ruleset            types.Ruleset
	response           types.ResponseConfig
	responseConfigured bool
	dispatch           types.DispatchConfig
	dispatchConfigured bool
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.responseConfigured, nil
}

func (r *InMemoryRuntime) GetResponse(ctx context.Context) (types.ResponseConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.responseConfigured {
		return defaultResponseConfig(), nil
	}
	return r.response, nil
}

func (r *InMemoryRuntime) ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error) {
	next, err := normalizeResponseConfig(config)
	if err != nil {
		return types.ResponseConfig{}, err
	}

	r.mu.Lock()
	r.response = next
	r.responseConfigured = true
	r.mu.Unlock()
	return next, nil
}

func (r *InMemoryRuntime) ClearResponse(ctx context.Context) error {
	r.mu.Lock()
	r.response = types.ResponseConfig{}
	r.responseConfigured = false
	r.mu.Unlock()
	return nil
}

func (r *InMemoryRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.dispatchConfigured {
		return false, nil
	}
	return r.dispatch.Enabled, nil
}

func (r *InMemoryRuntime) GetDispatch(ctx context.Context) (types.DispatchConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.dispatchConfigured {
		return defaultDispatchConfig(), nil
	}
	return r.dispatch, nil
}

func (r *InMemoryRuntime) ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error) {
	next, err := normalizeDispatchConfig(config)
	if err != nil {
		return types.DispatchConfig{}, err
	}

	r.mu.Lock()
	r.dispatch = next
	r.dispatchConfigured = true
	r.mu.Unlock()
	return next, nil
}

func (r *InMemoryRuntime) ClearDispatch(ctx context.Context) error {
	r.mu.Lock()
	r.dispatch = types.DispatchConfig{}
	r.dispatchConfigured = false
	r.mu.Unlock()
	return nil
}
