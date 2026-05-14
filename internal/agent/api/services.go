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

type AttachmentService interface {
	ListAttachments(ctx context.Context) ([]types.Attachment, error)
	GetAttachment(ctx context.Context, ifindex int) (types.Attachment, error)
	CreateAttachment(ctx context.Context, attachment types.Attachment, dryRun bool) (types.Attachment, error)
	SetAttachmentEnabled(ctx context.Context, ifindex int, enabled bool) (types.Attachment, error)
	DeleteAttachment(ctx context.Context, ifindex int) error
}

type ResponseService interface {
	GetResponse(ctx context.Context) (types.ResponseConfig, error)
	ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error)
	ClearResponse(ctx context.Context) error
}

type DispatchService interface {
	GetDispatch(ctx context.Context) (types.DispatchConfig, error)
	ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error)
	ClearDispatch(ctx context.Context) error
}
