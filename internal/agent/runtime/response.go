package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
)

type responseState struct {
	config     types.ResponseConfig
	configured bool
}

type dataplaneResponseRuntime struct {
	ifindex int
	runtime DataplaneRuntime
}

func (r *DataplaneAttachmentRuntime) ResponseConfigured(ctx context.Context) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.response.configured, nil
}

func (r *DataplaneAttachmentRuntime) GetResponse(ctx context.Context) (types.ResponseConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return currentResponseConfig(r.response), nil
}

func (r *DataplaneAttachmentRuntime) ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error) {
	next, err := normalizeDataplaneResponseConfig(config)
	if err != nil {
		return types.ResponseConfig{}, err
	}
	nextOptions := newXDPResponseOptions(next)

	r.mu.Lock()
	defer r.mu.Unlock()

	previous := r.response
	previousOptions := newXDPResponseOptions(currentResponseConfig(previous))
	entries := r.enabledResponseRuntimesLocked()

	if err := applyResponseLocked(entries, nextOptions, previousOptions); err != nil {
		return types.ResponseConfig{}, err
	}

	r.response = responseState{
		config:     cloneResponseConfig(next),
		configured: true,
	}
	logrus.WithFields(logrus.Fields{
		"ifindex":     next.IfIndex,
		"ifname":      next.IfName,
		"vlan_mode":   next.VLANMode,
		"attachments": len(entries),
	}).Info("Applied dataplane response config")
	return cloneResponseConfig(next), nil
}

func (r *DataplaneAttachmentRuntime) ClearResponse(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	previous := r.response
	previousOptions := newXDPResponseOptions(currentResponseConfig(previous))
	nextOptions := newXDPResponseOptions(defaultDataplaneResponseConfig())
	entries := r.enabledResponseRuntimesLocked()

	if err := applyResponseLocked(entries, nextOptions, previousOptions); err != nil {
		return err
	}

	r.response = responseState{}
	logrus.WithField("attachments", len(entries)).Info("Cleared dataplane response config")
	return nil
}

func applyResponseLocked(entries []dataplaneResponseRuntime, next dataplane.XDPResponseOptions, previous dataplane.XDPResponseOptions) error {
	applied := make([]dataplaneResponseRuntime, 0, len(entries))
	for _, entry := range entries {
		if err := entry.runtime.ReplaceXDPResponse(next); err != nil {
			if rollbackErr := rollbackResponse(applied, previous); rollbackErr != nil {
				logrus.WithError(rollbackErr).WithField("ifindex", entry.ifindex).Error("Fail to rollback dataplane response config")
				return fmt.Errorf("apply response config to attachment %d: %w; rollback failed: %w", entry.ifindex, err, rollbackErr)
			}
			return fmt.Errorf("apply response config to attachment %d: %w", entry.ifindex, err)
		}
		applied = append(applied, entry)
	}
	return nil
}

func rollbackResponse(entries []dataplaneResponseRuntime, previous dataplane.XDPResponseOptions) error {
	var joined error
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if err := entry.runtime.ReplaceXDPResponse(previous); err != nil {
			joined = errors.Join(joined, fmt.Errorf("rollback response config on attachment %d: %w", entry.ifindex, err))
		}
	}
	return joined
}

func (r *DataplaneAttachmentRuntime) enabledResponseRuntimesLocked() []dataplaneResponseRuntime {
	runtimes := r.enabledDataplaneRuntimesLocked()
	entries := make([]dataplaneResponseRuntime, 0, len(runtimes))
	for _, item := range runtimes {
		entries = append(entries, dataplaneResponseRuntime{
			ifindex: item.ifindex,
			runtime: item.runtime,
		})
	}
	return entries
}

func normalizeDataplaneResponseConfig(config types.ResponseConfig) (types.ResponseConfig, error) {
	if config.IfIndex <= 0 {
		return types.ResponseConfig{}, types.NewValidationError("ifindex must be greater than 0")
	}
	if config.VLANMode == "" {
		config.VLANMode = types.VLANModePreserve
	}
	switch config.VLANMode {
	case types.VLANModePreserve, types.VLANModeAccess:
	default:
		return types.ResponseConfig{}, types.NewValidationError("vlan_mode must be preserve or access")
	}
	return cloneResponseConfig(config), nil
}

func currentResponseConfig(state responseState) types.ResponseConfig {
	if !state.configured {
		return defaultDataplaneResponseConfig()
	}
	return cloneResponseConfig(state.config)
}

func defaultDataplaneResponseConfig() types.ResponseConfig {
	return types.ResponseConfig{VLANMode: types.VLANModePreserve}
}

func newXDPResponseOptions(config types.ResponseConfig) dataplane.XDPResponseOptions {
	return dataplane.XDPResponseOptions{
		EgressIfIndex:  config.IfIndex,
		VLANMode:       config.VLANMode,
		FailureVerdict: "pass",
	}
}

func cloneResponseConfig(config types.ResponseConfig) types.ResponseConfig {
	return types.ResponseConfig{
		IfIndex:  config.IfIndex,
		IfName:   config.IfName,
		VLANMode: config.VLANMode,
	}
}
