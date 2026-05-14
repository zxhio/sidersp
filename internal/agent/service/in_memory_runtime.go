package service

import (
	"context"
	"sync"

	"sidersp/internal/agent/types"
)

type InMemoryRuntime struct {
	mu                 sync.RWMutex
	attachments        map[int]types.Attachment
	ruleset            types.Ruleset
	response           types.ResponseConfig
	responseConfigured bool
	dispatch           types.DispatchConfig
	dispatchConfigured bool
}

func NewInMemoryRuntime() *InMemoryRuntime {
	return &InMemoryRuntime{
		attachments: make(map[int]types.Attachment),
	}
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.attachments), nil
}

func (r *InMemoryRuntime) ListAttachments(ctx context.Context) ([]types.Attachment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]types.Attachment, 0, len(r.attachments))
	for _, item := range r.attachments {
		items = append(items, cloneAttachment(item))
	}
	sortAttachments(items)
	return items, nil
}

func (r *InMemoryRuntime) GetAttachment(ctx context.Context, ifindex int) (types.Attachment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, ok := r.attachments[ifindex]
	if !ok {
		return types.Attachment{}, attachmentNotFound(ifindex)
	}
	return cloneAttachment(item), nil
}

func (r *InMemoryRuntime) ValidateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	return normalizeAttachment(attachment)
}

func (r *InMemoryRuntime) CreateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	next, err := normalizeAttachment(attachment)
	if err != nil {
		return types.Attachment{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.attachments[next.IfIndex]; ok {
		return types.Attachment{}, attachmentConflict(next.IfIndex)
	}
	r.attachments[next.IfIndex] = cloneAttachment(next)
	return cloneAttachment(next), nil
}

func (r *InMemoryRuntime) SetAttachmentEnabled(ctx context.Context, ifindex int, enabled bool) (types.Attachment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, ok := r.attachments[ifindex]
	if !ok {
		return types.Attachment{}, attachmentNotFound(ifindex)
	}
	item.Enabled = enabled
	item.Runtime.ProgramID = 0
	r.attachments[ifindex] = cloneAttachment(item)
	return cloneAttachment(item), nil
}

func (r *InMemoryRuntime) DeleteAttachment(ctx context.Context, ifindex int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.attachments[ifindex]; !ok {
		return attachmentNotFound(ifindex)
	}
	delete(r.attachments, ifindex)
	return nil
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
