package service

import "context"

type NoopRuntime struct{}

func (NoopRuntime) AttachmentCount(ctx context.Context) (int, error) {
	return 0, nil
}

func (NoopRuntime) RulesetVersion(ctx context.Context) (uint64, error) {
	return 0, nil
}

func (NoopRuntime) ResponseConfigured(ctx context.Context) (bool, error) {
	return false, nil
}

func (NoopRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	return false, nil
}
