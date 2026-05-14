package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type AttachmentRuntime interface {
	AttachmentCount(ctx context.Context) (int, error)
}

type AttachmentConfigRuntime interface {
	AttachmentRuntime
	ListAttachments(ctx context.Context) ([]types.Attachment, error)
	GetAttachment(ctx context.Context, ifindex int) (types.Attachment, error)
	ValidateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error)
	CreateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error)
	SetAttachmentEnabled(ctx context.Context, ifindex int, enabled bool) (types.Attachment, error)
	DeleteAttachment(ctx context.Context, ifindex int) error
}

type RulesetStatusRuntime interface {
	RulesetVersion(ctx context.Context) (uint64, error)
}

type RulesetRuntime interface {
	RulesetStatusRuntime
	GetRuleset(ctx context.Context) (types.Ruleset, error)
	ValidateRuleset(ctx context.Context, ruleset types.Ruleset) error
	ReplaceRuleset(ctx context.Context, ruleset types.Ruleset) (types.Ruleset, error)
	ClearRuleset(ctx context.Context) error
}

type ResponseRuntime interface {
	ResponseConfigured(ctx context.Context) (bool, error)
}

type ResponseConfigRuntime interface {
	ResponseRuntime
	GetResponse(ctx context.Context) (types.ResponseConfig, error)
	ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error)
	ClearResponse(ctx context.Context) error
}

type DispatchRuntime interface {
	DispatchEnabled(ctx context.Context) (bool, error)
}

type DispatchConfigRuntime interface {
	DispatchRuntime
	GetDispatch(ctx context.Context) (types.DispatchConfig, error)
	ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error)
	ClearDispatch(ctx context.Context) error
}

type RuntimeDeps struct {
	Attachments AttachmentRuntime
	Ruleset     RulesetStatusRuntime
	Response    ResponseRuntime
	Dispatch    DispatchRuntime
}

func NewNoopRuntimeDeps() RuntimeDeps {
	runtime := NoopRuntime{}
	return RuntimeDeps{
		Attachments: runtime,
		Ruleset:     runtime,
		Response:    runtime,
		Dispatch:    runtime,
	}
}
