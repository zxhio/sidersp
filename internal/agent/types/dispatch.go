package types

const (
	DispatchBackendAFPacket = "af_packet"
)

type DispatchConfig struct {
	Enabled        bool
	Backend        string
	TargetIfIndex  int
	TargetIfName   string
	VLANMode       string
	QueueSize      int
	MaxPacketBytes int
}
