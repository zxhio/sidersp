package service

import (
	"context"
	"fmt"
	"sort"

	"sidersp/internal/agent/types"
)

const (
	defaultAttachmentFrameSize      = 2048
	defaultAttachmentFrameCount     = 4096
	defaultAttachmentRingSize       = 2048
	defaultAttachmentTXFrameReserve = 256
)

type AttachmentService struct {
	runtime AttachmentConfigRuntime
}

func NewAttachmentService(runtime AttachmentConfigRuntime) *AttachmentService {
	if runtime == nil {
		panic("agent service: attachment runtime is required")
	}
	return &AttachmentService{runtime: runtime}
}

func (s *AttachmentService) ListAttachments(ctx context.Context) ([]types.Attachment, error) {
	return s.runtime.ListAttachments(ctx)
}

func (s *AttachmentService) GetAttachment(ctx context.Context, ifindex int) (types.Attachment, error) {
	if err := validateIfIndex(ifindex); err != nil {
		return types.Attachment{}, err
	}
	return s.runtime.GetAttachment(ctx, ifindex)
}

func (s *AttachmentService) CreateAttachment(ctx context.Context, attachment types.Attachment, dryRun bool) (types.Attachment, error) {
	if dryRun {
		return s.runtime.ValidateAttachment(ctx, attachment)
	}
	return s.runtime.CreateAttachment(ctx, attachment)
}

func (s *AttachmentService) SetAttachmentEnabled(ctx context.Context, ifindex int, enabled bool) (types.Attachment, error) {
	if err := validateIfIndex(ifindex); err != nil {
		return types.Attachment{}, err
	}
	return s.runtime.SetAttachmentEnabled(ctx, ifindex, enabled)
}

func (s *AttachmentService) DeleteAttachment(ctx context.Context, ifindex int) error {
	if err := validateIfIndex(ifindex); err != nil {
		return err
	}
	return s.runtime.DeleteAttachment(ctx, ifindex)
}

func normalizeAttachment(attachment types.Attachment) (types.Attachment, error) {
	if err := validateIfIndex(attachment.IfIndex); err != nil {
		return types.Attachment{}, err
	}
	if attachment.AttachMode == "" {
		attachment.AttachMode = types.AttachModeNative
	}
	if err := validateAttachMode(attachment.AttachMode); err != nil {
		return types.Attachment{}, err
	}
	if attachment.MissVerdict == "" {
		attachment.MissVerdict = types.MissVerdictPass
	}
	if err := validateMissVerdict(attachment.MissVerdict); err != nil {
		return types.Attachment{}, err
	}
	if err := normalizeAttachmentChannels(&attachment.Channels); err != nil {
		return types.Attachment{}, err
	}
	if err := normalizeAttachmentXSK(&attachment); err != nil {
		return types.Attachment{}, err
	}
	attachment.Enabled = true
	attachment.Runtime.ProgramID = 0
	return cloneAttachment(attachment), nil
}

func validateIfIndex(ifindex int) error {
	if ifindex <= 0 {
		return types.NewValidationError("ifindex must be greater than 0")
	}
	return nil
}

func validateAttachMode(value string) error {
	switch value {
	case types.AttachModeGeneric, types.AttachModeNative, types.AttachModeDriver:
		return nil
	default:
		return types.NewValidationError("attach_mode must be generic, native, or driver")
	}
}

func validateMissVerdict(value string) error {
	switch value {
	case types.MissVerdictPass, types.MissVerdictDrop:
		return nil
	default:
		return types.NewValidationError("miss_verdict must be pass or drop")
	}
}

func normalizeAttachmentChannels(channels *types.AttachmentChannels) error {
	if channels.RXQueueCount < 0 {
		return types.NewValidationError("channels.rx_queue_count must be greater than or equal to 0")
	}
	if channels.MaxRXQueueCount < 0 {
		return types.NewValidationError("channels.max_rx_queue_count must be greater than or equal to 0")
	}
	if channels.RXQueueCount > 0 && channels.MaxRXQueueCount > 0 && channels.RXQueueCount > channels.MaxRXQueueCount {
		return types.NewValidationError("channels.rx_queue_count must not exceed channels.max_rx_queue_count")
	}
	return nil
}

func normalizeAttachmentXSK(attachment *types.Attachment) error {
	if err := normalizeAttachmentUMEM(&attachment.XSK.UMEM); err != nil {
		return err
	}

	queueLimit := attachment.Channels.RXQueueCount
	if queueLimit == 0 {
		queueLimit = attachment.Channels.MaxRXQueueCount
	}
	if len(attachment.XSK.Queues) == 0 {
		attachment.XSK.Queues = defaultAttachmentQueues(queueLimit)
		return nil
	}
	if queueLimit == 0 {
		queueLimit = 1
	}
	return validateAttachmentQueues(attachment.XSK.Queues, queueLimit)
}

func normalizeAttachmentUMEM(umem *types.AttachmentUMEM) error {
	if umem.FrameSize == 0 {
		umem.FrameSize = defaultAttachmentFrameSize
	}
	switch umem.FrameSize {
	case 2048, 4096:
	default:
		return types.NewValidationError("xsk.umem.frame_size must be 2048 or 4096")
	}
	if err := normalizePowerOfTwo(&umem.FrameCount, defaultAttachmentFrameCount, "xsk.umem.frame_count"); err != nil {
		return err
	}
	if err := normalizePowerOfTwo(&umem.FillRingSize, defaultAttachmentRingSize, "xsk.umem.fill_ring_size"); err != nil {
		return err
	}
	if err := normalizePowerOfTwo(&umem.CompletionRingSize, defaultAttachmentRingSize, "xsk.umem.completion_ring_size"); err != nil {
		return err
	}
	if err := normalizePowerOfTwo(&umem.RXRingSize, defaultAttachmentRingSize, "xsk.umem.rx_ring_size"); err != nil {
		return err
	}
	if err := normalizePowerOfTwo(&umem.TXRingSize, defaultAttachmentRingSize, "xsk.umem.tx_ring_size"); err != nil {
		return err
	}
	if umem.TXFrameReserve == 0 {
		umem.TXFrameReserve = defaultAttachmentTXFrameReserve
	}
	if umem.TXFrameReserve < 0 {
		return types.NewValidationError("xsk.umem.tx_frame_reserve must be greater than or equal to 0")
	}
	if umem.TXFrameReserve >= umem.FrameSize {
		return types.NewValidationError("xsk.umem.tx_frame_reserve must be less than xsk.umem.frame_size")
	}
	return nil
}

func normalizePowerOfTwo(value *int, defaultValue int, field string) error {
	if *value == 0 {
		*value = defaultValue
	}
	if *value < 0 {
		return types.NewValidationError("%s must be greater than 0", field)
	}
	if !isPowerOfTwo(*value) {
		return types.NewValidationError("%s must be a power of two", field)
	}
	return nil
}

func isPowerOfTwo(value int) bool {
	return value > 0 && value&(value-1) == 0
}

func defaultAttachmentQueues(queueLimit int) []int {
	if queueLimit <= 0 {
		return []int{0}
	}
	queues := make([]int, queueLimit)
	for i := range queues {
		queues[i] = i
	}
	return queues
}

func validateAttachmentQueues(queues []int, queueLimit int) error {
	seen := make(map[int]struct{}, len(queues))
	for _, queue := range queues {
		if queue < 0 {
			return types.NewValidationError("xsk.queues contains negative queue %d", queue)
		}
		if queue >= queueLimit {
			return types.NewValidationError("xsk.queues queue %d must be less than enabled rx queue count %d", queue, queueLimit)
		}
		if _, ok := seen[queue]; ok {
			return types.NewValidationError("xsk.queues contains duplicate queue %d", queue)
		}
		seen[queue] = struct{}{}
	}
	return nil
}

func attachmentNotFound(ifindex int) types.NotFoundError {
	return types.NewNotFoundError(fmt.Sprintf("attachment %d not found", ifindex))
}

func attachmentConflict(ifindex int) types.ConflictError {
	return types.NewConflictError(fmt.Sprintf("attachment %d already exists", ifindex))
}

func cloneAttachments(items []types.Attachment) []types.Attachment {
	if items == nil {
		return nil
	}
	out := make([]types.Attachment, len(items))
	for i, item := range items {
		out[i] = cloneAttachment(item)
	}
	return out
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
