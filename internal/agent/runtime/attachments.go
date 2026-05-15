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
	"sidersp/internal/frameio/afxdp"
	"sidersp/internal/model"
	"sidersp/internal/xsk"
)

type DataplaneAttachmentRuntime struct {
	validator            service.AttachmentConfigRuntime
	opener               DataplaneOpener
	interfaceByIndex     interfaceLookup
	responseEgressWriter responseEgressWriterFactory

	mu                sync.RWMutex
	attachments       map[int]types.Attachment
	runtimes          map[int]DataplaneRuntime
	responseConsumers map[int]*responseConsumerSlot
	ruleset           types.Ruleset
	response          responseState
	dispatch          dispatchState

	dispatchApplier dispatchApplier
}

type openedDataplaneRuntime struct {
	runtime          DataplaneRuntime
	markXSKStarted   func() bool
	startXSK         func()
	responseConsumer *responseConsumerSlot
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
		validator:            validator,
		opener:               opener,
		interfaceByIndex:     interfaceByIndex,
		responseEgressWriter: newAFPacketWriter,
		attachments:          make(map[int]types.Attachment),
		runtimes:             make(map[int]DataplaneRuntime),
		responseConsumers:    make(map[int]*responseConsumerSlot),
		dispatchApplier:      noopDispatchApplier{},
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

	opened, err := r.openAttachment(next)
	if err != nil {
		return types.Attachment{}, err
	}
	runtime := opened.runtime
	if err := r.attachRuntimeState(&next, runtime); err != nil {
		r.closeOpenedRuntime(next.IfIndex, opened)
		return types.Attachment{}, err
	}
	r.mu.Lock()
	if _, ok := r.attachments[next.IfIndex]; ok {
		r.mu.Unlock()
		r.closeOpenedRuntime(next.IfIndex, opened)
		return types.Attachment{}, attachmentConflict(next.IfIndex)
	}
	if err := r.replayDesiredStateToRuntimeLocked(ctx, next.IfIndex, runtime); err != nil {
		r.mu.Unlock()
		r.closeOpenedRuntime(next.IfIndex, opened)
		return types.Attachment{}, err
	}
	if err := r.replayResponseConsumerLocked(next, opened.responseConsumer); err != nil {
		r.mu.Unlock()
		r.closeOpenedRuntime(next.IfIndex, opened)
		return types.Attachment{}, err
	}
	r.attachments[next.IfIndex] = cloneAttachment(next)
	r.runtimes[next.IfIndex] = runtime
	if opened.responseConsumer != nil {
		r.responseConsumers[next.IfIndex] = opened.responseConsumer
	}
	r.mu.Unlock()
	startOpenedXSK(opened)

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
	opened, err := r.openAttachment(next)
	if err != nil {
		return types.Attachment{}, err
	}
	runtime := opened.runtime
	if err := r.attachRuntimeState(&next, runtime); err != nil {
		r.closeOpenedRuntime(ifindex, opened)
		return types.Attachment{}, err
	}
	r.mu.Lock()
	if _, ok := r.attachments[ifindex]; !ok {
		r.mu.Unlock()
		r.closeOpenedRuntime(ifindex, opened)
		return types.Attachment{}, attachmentNotFound(ifindex)
	}
	if err := r.replayDesiredStateToRuntimeLocked(ctx, ifindex, runtime); err != nil {
		r.mu.Unlock()
		r.closeOpenedRuntime(ifindex, opened)
		return types.Attachment{}, err
	}
	if err := r.replayResponseConsumerLocked(next, opened.responseConsumer); err != nil {
		r.mu.Unlock()
		r.closeOpenedRuntime(ifindex, opened)
		return types.Attachment{}, err
	}
	r.attachments[ifindex] = cloneAttachment(next)
	r.runtimes[ifindex] = runtime
	if opened.responseConsumer != nil {
		r.responseConsumers[ifindex] = opened.responseConsumer
	}
	r.mu.Unlock()
	startOpenedXSK(opened)

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
	var responseTotal model.ResponseStats
	for _, consumer := range r.activeResponseConsumers() {
		addResponseStats(&responseTotal, consumer.ReadStats())
	}
	return service.NewStatsFromRuntime(model.RuntimeStats{
		Dataplane: total,
		Response:  responseTotal,
	}), nil
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
	for ifindex, consumer := range r.responseConsumers {
		if err := consumer.Close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("close response consumer for attachment %d: %w", ifindex, err)
		}
		delete(r.responseConsumers, ifindex)
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

func (r *DataplaneAttachmentRuntime) openAttachment(attachment types.Attachment) (openedDataplaneRuntime, error) {
	options := newDataplaneOptions(attachment)
	consumers, responseConsumer, err := r.newXSKConsumers(attachment)
	if err != nil {
		return openedDataplaneRuntime{}, err
	}
	runtime, err := r.opener(options, consumers)
	if err != nil {
		if responseConsumer != nil {
			_ = responseConsumer.Close()
		}
		return openedDataplaneRuntime{}, fmt.Errorf("open dataplane attachment %d: %w", attachment.IfIndex, err)
	}
	if err := runtime.Attach(); err != nil {
		if closeErr := runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", attachment.IfIndex).Error("Fail to close dataplane runtime")
		}
		if responseConsumer != nil {
			_ = responseConsumer.Close()
		}
		return openedDataplaneRuntime{}, fmt.Errorf("attach dataplane attachment %d: %w", attachment.IfIndex, err)
	}
	if attachment.XSK.Enabled {
		managed := newManagedDataplaneRuntime(attachment.IfIndex, runtime)
		return openedDataplaneRuntime{
			runtime:          managed,
			markXSKStarted:   managed.markXSKStarted,
			startXSK:         managed.runXSK,
			responseConsumer: responseConsumer,
		}, nil
	}
	return openedDataplaneRuntime{runtime: runtime, responseConsumer: responseConsumer}, nil
}

func startOpenedXSK(opened openedDataplaneRuntime) {
	if opened.startXSK == nil {
		return
	}
	if opened.markXSKStarted != nil && !opened.markXSKStarted() {
		return
	}
	go opened.startXSK()
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
	consumer := r.responseConsumers[ifindex]
	r.mu.RUnlock()

	if runtime == nil {
		return nil
	}
	if err := runtime.Close(); err != nil {
		return fmt.Errorf("close dataplane attachment %d: %w", ifindex, err)
	}
	if consumer != nil {
		if err := consumer.Close(); err != nil {
			return fmt.Errorf("close response consumer for attachment %d: %w", ifindex, err)
		}
	}

	r.mu.Lock()
	if r.runtimes[ifindex] == runtime {
		delete(r.runtimes, ifindex)
	}
	if r.responseConsumers[ifindex] == consumer {
		delete(r.responseConsumers, ifindex)
	}
	r.mu.Unlock()
	return nil
}

func (r *DataplaneAttachmentRuntime) closeOpenedRuntime(ifindex int, opened openedDataplaneRuntime) {
	if opened.runtime != nil {
		if closeErr := opened.runtime.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", ifindex).Error("Fail to close dataplane runtime")
		}
	}
	if opened.responseConsumer != nil {
		if closeErr := opened.responseConsumer.Close(); closeErr != nil {
			logrus.WithError(closeErr).WithField("ifindex", ifindex).Error("Fail to close response consumer")
		}
	}
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

func (r *DataplaneAttachmentRuntime) activeResponseConsumers() []*responseConsumerSlot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	items := make([]*responseConsumerSlot, 0, len(r.responseConsumers))
	for ifindex, consumer := range r.responseConsumers {
		if _, ok := r.runtimes[ifindex]; !ok || consumer == nil {
			continue
		}
		items = append(items, consumer)
	}
	return items
}

func addDataplaneStats(total *model.DataplaneStats, stats model.DataplaneStats) {
	total.RXPackets += stats.RXPackets
	total.ParseOKPackets += stats.ParseOKPackets
	total.ParseFailed += stats.ParseFailed
	total.RuleCandidates += stats.RuleCandidates
	total.MatchedRules += stats.MatchedRules
	total.MatchMissPackets += stats.MatchMissPackets
	total.KernelResponsePackets += stats.KernelResponsePackets
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

func addResponseStats(total *model.ResponseStats, stats model.ResponseStats) {
	total.XSKRXPackets += stats.XSKRXPackets
	total.ResponseSent += stats.ResponseSent
	total.ResponseFailed += stats.ResponseFailed
	total.AFXDPTX += stats.AFXDPTX
	total.AFXDPTXFailed += stats.AFXDPTXFailed
	total.AFPacketTX += stats.AFPacketTX
	total.AFPacketTXFailed += stats.AFPacketTXFailed
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
	options := dataplane.Options{
		Interface:        attachment.IfName,
		AttachMode:       attachment.AttachMode,
		CombinedChannels: enabledRXQueueCount(attachment.Channels),
		IngressVerdict:   attachment.MissVerdict,
		XDPResponse: dataplane.XDPResponseOptions{
			VLANMode:       "preserve",
			FailureVerdict: "pass",
		},
	}
	if attachment.XSK.Enabled {
		options.XSK = newXSKOptions(attachment)
	}
	return options
}

func enabledRXQueueCount(channels types.AttachmentChannels) int {
	if channels.RXQueueCount > 0 {
		return channels.RXQueueCount
	}
	if channels.MaxRXQueueCount > 0 {
		return channels.MaxRXQueueCount
	}
	return 0
}

func newXSKOptions(attachment types.Attachment) xsk.Options {
	afxdpConfig := afxdp.DefaultSocketConfig()
	afxdpConfig.IfIndex = attachment.IfIndex
	afxdpConfig.FrameSize = uint32(attachment.XSK.UMEM.FrameSize)
	afxdpConfig.FrameCount = uint32(attachment.XSK.UMEM.FrameCount)
	afxdpConfig.FillRingSize = uint32(attachment.XSK.UMEM.FillRingSize)
	afxdpConfig.CompletionRingSize = uint32(attachment.XSK.UMEM.CompletionRingSize)
	afxdpConfig.RXRingSize = uint32(attachment.XSK.UMEM.RXRingSize)
	afxdpConfig.TXRingSize = uint32(attachment.XSK.UMEM.TXRingSize)
	afxdpConfig.TXFrameReserve = uint32(attachment.XSK.UMEM.TXFrameReserve)

	return xsk.Options{
		Enabled: true,
		IfIndex: attachment.IfIndex,
		Queues:  append([]int(nil), attachment.XSK.Queues...),
		AFXDP:   afxdpConfig,
	}
}

func (r *DataplaneAttachmentRuntime) Events() []model.EventRecord {
	runtime := r.firstRuntime()
	if runtime == nil {
		return nil
	}
	return runtime.Events()
}
