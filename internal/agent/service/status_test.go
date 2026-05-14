package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatusReadsRuntimeState(t *testing.T) {
	svc := NewStatusServiceWithRuntime(RuntimeDeps{
		Attachments: fakeAttachmentRuntime{count: 2},
		Ruleset:     fakeRulesetRuntime{version: 7},
		Response:    fakeResponseRuntime{configured: true},
		Dispatch:    fakeDispatchRuntime{enabled: true},
	})

	status, err := svc.Status(context.Background())

	require.NoError(t, err)
	require.Equal(t, 2, status.Attachments)
	require.Equal(t, uint64(7), status.RulesetVersion)
	require.True(t, status.ResponseConfigured)
	require.True(t, status.DispatchEnabled)
}

func TestDefaultStatusServiceUsesNoopRuntime(t *testing.T) {
	status, err := NewStatusService().Status(context.Background())

	require.NoError(t, err)
	require.Zero(t, status.Attachments)
	require.Zero(t, status.RulesetVersion)
	require.False(t, status.ResponseConfigured)
	require.False(t, status.DispatchEnabled)
}

type fakeAttachmentRuntime struct {
	count int
}

func (r fakeAttachmentRuntime) AttachmentCount(ctx context.Context) (int, error) {
	return r.count, nil
}

type fakeRulesetRuntime struct {
	version uint64
}

func (r fakeRulesetRuntime) RulesetVersion(ctx context.Context) (uint64, error) {
	return r.version, nil
}

type fakeResponseRuntime struct {
	configured bool
}

func (r fakeResponseRuntime) ResponseConfigured(ctx context.Context) (bool, error) {
	return r.configured, nil
}

type fakeDispatchRuntime struct {
	enabled bool
}

func (r fakeDispatchRuntime) DispatchEnabled(ctx context.Context) (bool, error) {
	return r.enabled, nil
}
