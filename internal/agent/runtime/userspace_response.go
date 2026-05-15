package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/frameio"
	"sidersp/internal/model"
	"sidersp/internal/response"
	"sidersp/internal/rule"
	"sidersp/internal/xsk"
)

type responseConsumer interface {
	xsk.ResponseConsumer
	xsk.ResponseErrorRecorder
	io.Closer
	ReplaceRules(rule.RuleSet) error
	ReadStats() model.ResponseStats
}

const agentResponseResultBufferSize = 1024

type responseConsumerSlot struct {
	mu      sync.RWMutex
	current responseConsumer
}

func (s *responseConsumerSlot) HandleXSK(ctx context.Context, envelope xsk.Envelope, socket xsk.Socket) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	current := s.current
	if current == nil {
		return fmt.Errorf("handle xsk response: consumer is not configured")
	}
	return current.HandleXSK(ctx, envelope, socket)
}

func (s *responseConsumerSlot) RecordXSKError(ctx context.Context, queueID int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	current := s.current
	if current == nil {
		return
	}
	current.RecordXSKError(ctx, queueID, err)
}

func (s *responseConsumerSlot) Replace(next responseConsumer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.current != nil {
		if err := s.current.Close(); err != nil {
			if next != nil {
				_ = next.Close()
			}
			return err
		}
	}
	s.current = next
	return nil
}

func (s *responseConsumerSlot) ReplaceRules(set rule.RuleSet) error {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	if current == nil {
		return nil
	}
	return current.ReplaceRules(set)
}

func (s *responseConsumerSlot) ReadStats() model.ResponseStats {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	if current == nil {
		return model.ResponseStats{}
	}
	return current.ReadStats()
}

func (s *responseConsumerSlot) Close() error {
	s.mu.Lock()
	current := s.current
	s.current = nil
	s.mu.Unlock()
	if current == nil {
		return nil
	}
	return current.Close()
}

func (r *DataplaneAttachmentRuntime) newXSKConsumers(attachment types.Attachment) (dataplane.XSKConsumers, *responseConsumerSlot, error) {
	if !attachment.XSK.Enabled {
		return dataplane.XSKConsumers{}, nil, nil
	}

	slot := &responseConsumerSlot{}
	return dataplane.XSKConsumers{Response: slot}, slot, nil
}

func (r *DataplaneAttachmentRuntime) replayResponseConsumerLocked(attachment types.Attachment, consumer *responseConsumerSlot) error {
	if consumer == nil {
		return nil
	}
	next, err := r.newResponseConsumer(attachment, currentResponseConfig(r.response))
	if err != nil {
		return fmt.Errorf("replay response consumer to attachment %d: %w", attachment.IfIndex, err)
	}
	if err := consumer.Replace(next); err != nil {
		return fmt.Errorf("replay response consumer to attachment %d: %w", attachment.IfIndex, err)
	}
	return nil
}

func (r *DataplaneAttachmentRuntime) replaceResponseConsumersLocked(config types.ResponseConfig, previous types.ResponseConfig) error {
	entries := r.enabledResponseConsumersLocked()
	replaced := make([]responseConsumerRuntime, 0, len(entries))
	for _, entry := range entries {
		next, err := r.newResponseConsumer(entry.attachment, config)
		if err != nil {
			if rollbackErr := r.rollbackResponseConsumers(replaced, previous); rollbackErr != nil {
				return fmt.Errorf("build response consumer for attachment %d: %w; rollback failed: %w", entry.attachment.IfIndex, err, rollbackErr)
			}
			return fmt.Errorf("build response consumer for attachment %d: %w", entry.attachment.IfIndex, err)
		}
		if err := entry.consumer.Replace(next); err != nil {
			if rollbackErr := r.rollbackResponseConsumers(replaced, previous); rollbackErr != nil {
				return fmt.Errorf("replace response consumer for attachment %d: %w; rollback failed: %w", entry.attachment.IfIndex, err, rollbackErr)
			}
			return fmt.Errorf("replace response consumer for attachment %d: %w", entry.attachment.IfIndex, err)
		}
		replaced = append(replaced, entry)
	}
	return nil
}

func (r *DataplaneAttachmentRuntime) rollbackResponseConsumers(entries []responseConsumerRuntime, previous types.ResponseConfig) error {
	var joined error
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		next, err := r.newResponseConsumer(entry.attachment, previous)
		if err != nil {
			joined = errors.Join(joined, fmt.Errorf("build previous response consumer for attachment %d: %w", entry.attachment.IfIndex, err))
			continue
		}
		if err := entry.consumer.Replace(next); err != nil {
			joined = errors.Join(joined, fmt.Errorf("rollback response consumer for attachment %d: %w", entry.attachment.IfIndex, err))
		}
	}
	return joined
}

type responseConsumerRuntime struct {
	attachment types.Attachment
	consumer   *responseConsumerSlot
}

func (r *DataplaneAttachmentRuntime) enabledResponseConsumersLocked() []responseConsumerRuntime {
	entries := make([]responseConsumerRuntime, 0, len(r.responseConsumers))
	for ifindex, consumer := range r.responseConsumers {
		attachment, ok := r.attachments[ifindex]
		if !ok || !attachment.Enabled || consumer == nil {
			continue
		}
		entries = append(entries, responseConsumerRuntime{
			attachment: cloneAttachment(attachment),
			consumer:   consumer,
		})
	}
	return entries
}

func (r *DataplaneAttachmentRuntime) newResponseConsumer(attachment types.Attachment, config types.ResponseConfig) (responseConsumer, error) {
	opts, writer, err := r.newResponseRuntimeOptions(attachment, config)
	if err != nil {
		return nil, err
	}
	runtime, err := response.NewRuntime(opts, writer)
	if err != nil {
		if writer != nil {
			_ = writer.Close()
		}
		return nil, err
	}
	rules, err := currentDataplaneRuleSet(r.ruleset)
	if err != nil {
		_ = runtime.Close()
		return nil, err
	}
	if err := runtime.ReplaceRules(rules); err != nil {
		_ = runtime.Close()
		return nil, err
	}
	return runtime, nil
}

func (r *DataplaneAttachmentRuntime) newResponseRuntimeOptions(attachment types.Attachment, config types.ResponseConfig) (response.Options, frameio.WriteCloser, error) {
	txIfIndex := attachment.IfIndex
	txIfName := attachment.IfName
	if config.IfIndex > 0 {
		iface, err := r.interfaceByIndex(config.IfIndex)
		if err != nil {
			return response.Options{}, nil, fmt.Errorf("lookup response interface %d: %w", config.IfIndex, err)
		}
		txIfIndex = iface.Index
		txIfName = iface.Name
	}

	hardwareAddr, err := r.responseHardwareAddr(txIfIndex)
	if err != nil {
		return response.Options{}, nil, err
	}

	opts := response.Options{
		Enabled:          true,
		IfIndex:          attachment.IfIndex,
		ResultBufferSize: agentResponseResultBufferSize,
		HardwareAddr:     hardwareAddr,
		EgressInterface:  responseEgressInterface(attachment, config, txIfName),
	}
	var writer frameio.WriteCloser
	if opts.EgressInterface != "" {
		if r.responseEgressWriter == nil {
			return response.Options{}, nil, fmt.Errorf("create response egress writer: factory is required")
		}
		writer, err = r.responseEgressWriter(opts.EgressInterface)
		if err != nil {
			return response.Options{}, nil, fmt.Errorf("create response egress writer for %s: %w", opts.EgressInterface, err)
		}
	}
	return opts, writer, nil
}

func (r *DataplaneAttachmentRuntime) responseHardwareAddr(ifindex int) ([]byte, error) {
	iface, err := r.interfaceByIndex(ifindex)
	if err != nil {
		return nil, fmt.Errorf("lookup response tx interface %d: %w", ifindex, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("response tx interface %q must have a 6-byte ethernet hardware address", iface.Name)
	}
	return append([]byte(nil), iface.HardwareAddr...), nil
}

func responseEgressInterface(attachment types.Attachment, config types.ResponseConfig, txIfName string) string {
	if config.IfIndex <= 0 || config.IfIndex == attachment.IfIndex {
		return ""
	}
	return txIfName
}
