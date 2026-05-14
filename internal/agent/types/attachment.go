package types

const (
	AttachModeGeneric = "generic"
	AttachModeNative  = "native"
	AttachModeDriver  = "driver"

	MissVerdictPass = "pass"
	MissVerdictDrop = "drop"
)

type Attachment struct {
	IfIndex     int
	IfName      string
	AttachMode  string
	Enabled     bool
	MissVerdict string
	Channels    AttachmentChannels
	XSK         AttachmentXSK
	Runtime     AttachmentRuntimeState
}

type AttachmentChannels struct {
	RXQueueCount    int
	MaxRXQueueCount int
}

type AttachmentXSK struct {
	Enabled bool
	Queues  []int
	UMEM    AttachmentUMEM
}

type AttachmentUMEM struct {
	FrameSize          int
	FrameCount         int
	FillRingSize       int
	CompletionRingSize int
	RXRingSize         int
	TXRingSize         int
	TXFrameReserve     int
}

type AttachmentRuntimeState struct {
	ProgramID uint32
}
