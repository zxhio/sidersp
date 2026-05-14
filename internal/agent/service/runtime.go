package service

import "context"

type AttachmentRuntime interface {
	AttachmentCount(ctx context.Context) (int, error)
}

type RulesetRuntime interface {
	RulesetVersion(ctx context.Context) (uint64, error)
}

type ResponseRuntime interface {
	ResponseConfigured(ctx context.Context) (bool, error)
}

type DispatchRuntime interface {
	DispatchEnabled(ctx context.Context) (bool, error)
}

type RuntimeDeps struct {
	Attachments AttachmentRuntime
	Ruleset     RulesetRuntime
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
