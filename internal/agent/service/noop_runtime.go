package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type NoopRuntime struct{}

func (NoopRuntime) AttachmentCount(ctx context.Context) (int, error) {
	return 0, nil
}

func (NoopRuntime) ListAttachments(ctx context.Context) ([]types.Attachment, error) {
	return nil, nil
}

func (NoopRuntime) GetAttachment(ctx context.Context, ifindex int) (types.Attachment, error) {
	return types.Attachment{}, attachmentNotFound(ifindex)
}

func (NoopRuntime) ValidateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	return normalizeAttachment(attachment)
}

func (NoopRuntime) CreateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	return normalizeAttachment(attachment)
}

func (NoopRuntime) SetAttachmentEnabled(ctx context.Context, ifindex int, enabled bool) (types.Attachment, error) {
	return types.Attachment{}, attachmentNotFound(ifindex)
}

func (NoopRuntime) DeleteAttachment(ctx context.Context, ifindex int) error {
	return attachmentNotFound(ifindex)
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

func (NoopRuntime) GetResponse(ctx context.Context) (types.ResponseConfig, error) {
	return defaultResponseConfig(), nil
}

func (NoopRuntime) ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error) {
	return normalizeResponseConfig(config)
}

func (NoopRuntime) ClearResponse(ctx context.Context) error {
	return nil
}

func (NoopRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	return false, nil
}

func (NoopRuntime) GetDispatch(ctx context.Context) (types.DispatchConfig, error) {
	return defaultDispatchConfig(), nil
}

func (NoopRuntime) ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error) {
	return normalizeDispatchConfig(config)
}

func (NoopRuntime) ClearDispatch(ctx context.Context) error {
	return nil
}
