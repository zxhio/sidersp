package types

const (
	VLANModePreserve = "preserve"
	VLANModeAccess   = "access"
)

type ResponseConfig struct {
	IfIndex  int
	IfName   string
	VLANMode string
}
