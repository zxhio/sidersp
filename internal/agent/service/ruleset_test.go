package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
)

func TestRulesetDryRunDoesNotModifyCurrentRuleset(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewRulesetService(runtime)
	current := testRuleset(1, 1001)
	_, err := svc.ReplaceRuleset(context.Background(), current, false)
	require.NoError(t, err)

	next := testRuleset(2, 1002)
	got, err := svc.ReplaceRuleset(context.Background(), next, true)

	require.NoError(t, err)
	require.Equal(t, next.Version, got.Version)

	stored, err := svc.GetRuleset(context.Background())
	require.NoError(t, err)
	require.Equal(t, current.Version, stored.Version)
	require.Equal(t, current.Rules[0].RuleID, stored.Rules[0].RuleID)
}

func TestRulesetReplaceUpdatesCurrentRuleset(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewRulesetService(runtime)

	next := testRuleset(3, 1003)
	got, err := svc.ReplaceRuleset(context.Background(), next, false)

	require.NoError(t, err)
	require.Equal(t, next.Version, got.Version)

	stored, err := svc.GetRuleset(context.Background())
	require.NoError(t, err)
	require.Equal(t, next.Version, stored.Version)
	require.Equal(t, next.Rules[0].RuleID, stored.Rules[0].RuleID)

	version, err := runtime.RulesetVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, next.Version, version)
}

func TestRulesetClearResetsCurrentRuleset(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewRulesetService(runtime)
	_, err := svc.ReplaceRuleset(context.Background(), testRuleset(4, 1004), false)
	require.NoError(t, err)

	require.NoError(t, svc.ClearRuleset(context.Background()))

	stored, err := svc.GetRuleset(context.Background())
	require.NoError(t, err)
	require.Zero(t, stored.Version)
	require.Nil(t, stored.Rules)
}

func TestRulesetValidationRejectsInvalidRuleset(t *testing.T) {
	runtime := NewInMemoryRuntime()
	svc := NewRulesetService(runtime)

	_, err := svc.ReplaceRuleset(context.Background(), types.Ruleset{
		Version: 1,
		Rules: []types.Rule{
			{RuleID: 1005},
		},
	}, false)

	require.ErrorContains(t, err, "response.action is required")
}

func testRuleset(version uint64, ruleID uint32) types.Ruleset {
	return types.Ruleset{
		Version: version,
		Rules: []types.Rule{
			{
				RuleID:   ruleID,
				Priority: 10,
				Response: types.RuleResponse{Action: "alert"},
			},
		},
	}
}
