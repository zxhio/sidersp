package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type AttachmentRuntime interface {
	AttachmentCount(ctx context.Context) (int, error)
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

type DispatchRuntime interface {
	DispatchEnabled(ctx context.Context) (bool, error)
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
