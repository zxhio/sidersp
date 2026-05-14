package runtime

import (
	"context"
	"fmt"
)

func (r *DataplaneAttachmentRuntime) replayDesiredStateToRuntimeLocked(ctx context.Context, ifindex int, runtime DataplaneRuntime) error {
	response := newXDPResponseOptions(currentResponseConfig(r.response))
	if err := runtime.ReplaceXDPResponse(response); err != nil {
		return fmt.Errorf("replay response config to attachment %d: %w", ifindex, err)
	}

	dispatch := currentDispatchConfig(r.dispatch)
	if err := r.dispatchApplier.ApplyDispatch(ctx, dispatch); err != nil {
		return fmt.Errorf("replay dispatch config to attachment %d: %w", ifindex, err)
	}

	rules, err := currentDataplaneRuleSet(r.ruleset)
	if err != nil {
		return err
	}
	if err := runtime.ReplaceRules(rules); err != nil {
		return fmt.Errorf("replay ruleset to attachment %d: %w", ifindex, err)
	}
	return nil
}
