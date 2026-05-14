package runtime

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/dataplane"
	"sidersp/internal/model"
)

type DataplaneAttachmentRuntime struct {
	validator        service.AttachmentConfigRuntime
	opener           DataplaneOpener
	interfaceByIndex interfaceLookup

	mu          sync.RWMutex
	attachments map[int]types.Attachment
	runtimes    map[int]DataplaneRuntime
	ruleset     types.Ruleset
	response    responseState
	dispatch    dispatchState

	dispatchApplier dispatchApplier
}

func NewDataplaneAttachmentRuntime(validator service.AttachmentConfigRuntime, opener DataplaneOpener, interfaceByIndex interfaceLookup) *DataplaneAttachmentRuntime {
	if validator == nil {
		panic("agent runtime: attachment validator is required")
	}
	if opener == nil {
		panic("agent runtime: dataplane opener is required")
	}
	if interfaceByIndex == nil {
		panic("agent runtime: interface lookup is required")
	}
	return &DataplaneAttachmentRuntime{
		validator:        validator,
		opener:           opener,
		interfaceByIndex: interfaceByIndex,
		attachments:      make(map[int]types.Attachment),
		runtimes:         make(map[int]DataplaneRuntime),
		dispatchApplier:  noopDispatchApplier{},
	}
}

func (r *DataplaneAttachmentRuntime) AttachmentCount(ctx context.Context) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.attachments), nil
}

func (r *DataplaneAttachmentRuntime) ListAttachments(ctx context.Context) ([]types.Attachment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]types.Attachment, 0, len(r.attachments))
	for _, item := range r.attachments {
		items = append(items, cloneAttachment(item))
	}
	sortAttachments(items)
	return items, nil
}

func (r *DataplaneAttachmentRuntime) GetAttachment(ctx context.Context, ifindex int) (types.Attachment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	item, ok := r.attachments[ifindex]
	if !ok {
		return types.Attachment{}, attachmentNotFound(ifindex)
	}
	return cloneAttachment(item), nil
}

func (r *DataplaneAttachmentRuntime) ValidateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	return r.normalize(ctx, attachment)
}

func (r *DataplaneAttachmentRuntime) CreateAttachment(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	next, err := r.normalize(ctx, attachment)
	if err != nil {
		return types.Attachment{}, err
	}
	if r.hasAttachment(next.IfIndex) {
		return types.Attachment{}, attachmentConflict(next.IfIndex)
	}

	runtime, err := r.openAttachment(next)
	if err != nil {
		return types.Attachment{}, err
	}
	if err := r.attachRuntimeState(&next, runtime); err != nil {
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", next.IfIndex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, err
	}
	r.mu.Lock()
	if _, ok := r.attachments[next.IfIndex]; ok {
		r.mu.Unlock()
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", next.IfIndex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, attachmentConflict(next.IfIndex)
	}
	if err := r.applyCurrentRulesetToRuntimeLocked(next.IfIndex, runtime); err != nil {
		r.mu.Unlock()
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", next.IfIndex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, err
	}
	if err := r.applyCurrentResponseToRuntimeLocked(next.IfIndex, runtime); err != nil {
		r.mu.Unlock()
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", next.IfIndex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, err
	}
	r.attachments[next.IfIndex] = cloneAttachment(next)
	r.runtimes[next.IfIndex] = runtime
	r.mu.Unlock()

	logrus.WithFields(logrus.Fields{
		"ifindex": next.IfIndex,
		"ifname":  next.IfName,
	}).Info("Opened dataplane attachment")
	return cloneAttachment(next), nil
}

func (r *DataplaneAttachmentRuntime) SetAttachmentEnabled(ctx context.Context, ifindex int, enabled bool) (types.Attachment, error) {
	current, err := r.GetAttachment(ctx, ifindex)
	if err != nil {
		return types.Attachment{}, err
	}
	if current.Enabled == enabled {
		return current, nil
	}

	if !enabled {
		if err := r.closeRuntime(ifindex); err != nil {
			return types.Attachment{}, err
		}
		next := current
		next.Enabled = false
		next.Runtime.ProgramID = 0
		r.storeAttachment(next)
		logrus.WithFields(logrus.Fields{
			"ifindex": next.IfIndex,
			"ifname":  next.IfName,
		}).Info("Closed dataplane attachment")
		return cloneAttachment(next), nil
	}

	next := current
	next.Enabled = true
	runtime, err := r.openAttachment(next)
	if err != nil {
		return types.Attachment{}, err
	}
	if err := r.attachRuntimeState(&next, runtime); err != nil {
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", ifindex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, err
	}
	r.mu.Lock()
	if _, ok := r.attachments[ifindex]; !ok {
		r.mu.Unlock()
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", ifindex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, attachmentNotFound(ifindex)
	}
	if err := r.applyCurrentRulesetToRuntimeLocked(ifindex, runtime); err != nil {
		r.mu.Unlock()
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", ifindex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, err
	}
	if err := r.applyCurrentResponseToRuntimeLocked(ifindex, runtime); err != nil {
		r.mu.Unlock()
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", ifindex).Error("Fail to close dataplane runtime")
		}
		return types.Attachment{}, err
	}
	r.attachments[ifindex] = cloneAttachment(next)
	r.runtimes[ifindex] = runtime
	r.mu.Unlock()

	logrus.WithFields(logrus.Fields{
		"ifindex": next.IfIndex,
		"ifname":  next.IfName,
	}).Info("Opened dataplane attachment")
	return cloneAttachment(next), nil
}

func (r *DataplaneAttachmentRuntime) DeleteAttachment(ctx context.Context, ifindex int) error {
	if _, err := r.GetAttachment(ctx, ifindex); err != nil {
		return err
	}
	if err := r.closeRuntime(ifindex); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.attachments, ifindex)
	r.mu.Unlock()
	return nil
}

func (r *DataplaneAttachmentRuntime) ReadStats(ctx context.Context) (types.Stats, error) {
	var total model.DataplaneStats
	for _, runtime := range r.activeRuntimes() {
		stats, err := runtime.ReadStats()
		if err != nil {
			return types.Stats{}, err
		}
		addDataplaneStats(&total, stats)
	}
	return service.NewStatsFromDataplane(total), nil
}

func (r *DataplaneAttachmentRuntime) SubscribeEvents(ctx context.Context) (<-chan types.Event, error) {
	return nil, service.ErrEventStreamUnsupported
}

func (r *DataplaneAttachmentRuntime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var closeErr error
	for ifindex, runtime := range r.runtimes {
		if err := runtime.Close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("close dataplane attachment %d: %w", ifindex, err)
		}
		delete(r.runtimes, ifindex)
	}
	return closeErr
}

func (r *DataplaneAttachmentRuntime) normalize(ctx context.Context, attachment types.Attachment) (types.Attachment, error) {
	if attachment.IfIndex <= 0 {
		return types.Attachment{}, types.NewValidationError("ifindex must be greater than 0")
	}
	iface, err := r.interfaceByIndex(attachment.IfIndex)
	if err != nil {
		return types.Attachment{}, fmt.Errorf("lookup attachment interface %d: %w", attachment.IfIndex, err)
	}
	if attachment.IfName != "" && attachment.IfName != iface.Name {
		return types.Attachment{}, types.NewValidationError("ifname must match ifindex")
	}
	attachment.IfName = iface.Name
	if attachment.Channels.MaxRXQueueCount == 0 {
		attachment.Channels.MaxRXQueueCount = attachment.Channels.RXQueueCount
	}
	return r.validator.ValidateAttachment(ctx, attachment)
}

func (r *DataplaneAttachmentRuntime) openAttachment(attachment types.Attachment) (DataplaneRuntime, error) {
	options := newDataplaneOptions(attachment)
	runtime, err := r.opener(options)
	if err != nil {
		return nil, fmt.Errorf("open dataplane attachment %d: %w", attachment.IfIndex, err)
	}
	if err := runtime.Attach(); err != nil {
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", attachment.IfIndex).Error("Fail to close dataplane runtime")
		}
		return nil, fmt.Errorf("attach dataplane attachment %d: %w", attachment.IfIndex, err)
	}
	return runtime, nil
}

func (r *DataplaneAttachmentRuntime) attachRuntimeState(attachment *types.Attachment, runtime DataplaneRuntime) error {
	programID, err := runtime.ProgramID()
	if err != nil {
		return fmt.Errorf("read dataplane program id for attachment %d: %w", attachment.IfIndex, err)
	}
	attachment.Runtime.ProgramID = programID
	return nil
}

func (r *DataplaneAttachmentRuntime) closeRuntime(ifindex int) error {
	r.mu.RLock()
	runtime := r.runtimes[ifindex]
	r.mu.RUnlock()

	if runtime == nil {
		return nil
	}
	if err := runtime.Close(); err != nil {
		return fmt.Errorf("close dataplane attachment %d: %w", ifindex, err)
	}

	r.mu.Lock()
	if r.runtimes[ifindex] == runtime {
		delete(r.runtimes, ifindex)
	}
	r.mu.Unlock()
	return nil
}

func (r *DataplaneAttachmentRuntime) hasAttachment(ifindex int) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.attachments[ifindex]
	return ok
}

func (r *DataplaneAttachmentRuntime) storeAttachment(attachment types.Attachment) {
	r.mu.Lock()
	r.attachments[attachment.IfIndex] = cloneAttachment(attachment)
	r.mu.Unlock()
}

func (r *DataplaneAttachmentRuntime) firstRuntime() DataplaneRuntime {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, runtime := range r.runtimes {
		return runtime
	}
	return nil
}

func (r *DataplaneAttachmentRuntime) activeRuntimes() []DataplaneRuntime {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]DataplaneRuntime, 0, len(r.runtimes))
	for _, runtime := range r.runtimes {
		items = append(items, runtime)
	}
	return items
}

func addDataplaneStats(total *model.DataplaneStats, stats model.DataplaneStats) {
	total.RXPackets += stats.RXPackets
	total.ParseFailed += stats.ParseFailed
	total.RuleCandidates += stats.RuleCandidates
	total.MatchedRules += stats.MatchedRules
	total.RingbufDropped += stats.RingbufDropped
	total.XDPTX += stats.XDPTX
	total.TXFailed += stats.TXFailed
	total.XskRedirected += stats.XskRedirected
	total.XskRedirectFailed += stats.XskRedirectFailed
	total.XskMetaFailed += stats.XskMetaFailed
	total.XskMapRedirectFailed += stats.XskMapRedirectFailed
	total.RedirectTX += stats.RedirectTX
	total.RedirectFailed += stats.RedirectFailed
	total.FibLookupFailed += stats.FibLookupFailed
	if len(stats.RuleMatches) != 0 {
		if total.RuleMatches == nil {
			total.RuleMatches = make(map[uint32]uint64, len(stats.RuleMatches))
		}
		for ruleID, count := range stats.RuleMatches {
			total.RuleMatches[ruleID] += count
		}
	}
}

func cloneAttachment(item types.Attachment) types.Attachment {
	item.XSK.Queues = append([]int(nil), item.XSK.Queues...)
	return item
}

func sortAttachments(items []types.Attachment) {
	sort.Slice(items, func(i, j int) bool {
		return items[i].IfIndex < items[j].IfIndex
	})
}

func attachmentNotFound(ifindex int) types.NotFoundError {
	return types.NewNotFoundError(fmt.Sprintf("attachment %d not found", ifindex))
}

func attachmentConflict(ifindex int) types.ConflictError {
	return types.NewConflictError(fmt.Sprintf("attachment %d already exists", ifindex))
}

func newDataplaneOptions(attachment types.Attachment) dataplane.Options {
	return dataplane.Options{
		Interface:      attachment.IfName,
		AttachMode:     attachment.AttachMode,
		IngressVerdict: attachment.MissVerdict,
		XDPResponse: dataplane.XDPResponseOptions{
			VLANMode:       "preserve",
			FailureVerdict: "pass",
		},
	}
}

func (r *DataplaneAttachmentRuntime) Events() []model.EventRecord {
	runtime := r.firstRuntime()
	if runtime == nil {
		return nil
	}
	return runtime.Events()
}
