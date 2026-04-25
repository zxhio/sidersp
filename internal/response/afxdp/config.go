package afxdp

import (
	"fmt"
	"math/bits"

	"golang.org/x/sys/unix"
)

const (
	defaultFrameSize          = 4096
	defaultFrameCount         = 4096
	defaultFillRingSize       = 2048
	defaultCompletionRingSize = 2048
	defaultRXRingSize         = 2048
	defaultTXRingSize         = 2048
	defaultTXFrameReserve     = 256
	defaultBindFlags          = uint16(unix.XDP_COPY)
	xskMetadataHeadroom       = 8
)

// SocketConfig holds the configuration for creating AF_XDP sockets.
type SocketConfig struct {
	IfIndex   int
	BindFlags uint16 // e.g. XDP_COPY, XDP_USE_NEED_WAKEUP

	FrameSize          uint32 // bytes per frame, 2048 or 4096, default 4096
	FrameCount         uint32 // UMEM frame count, power of 2, default 4096
	FillRingSize       uint32 // fill ring entry count, power of 2, default 2048
	CompletionRingSize uint32 // completion ring entry count, power of 2, default 2048
	RXRingSize         uint32 // RX ring entry count, power of 2, default 2048
	TXRingSize         uint32 // TX ring entry count, power of 2, default 2048
	TXFrameReserve     uint32 // frames reserved for TX, default 256
}

// DefaultSocketConfig returns a SocketConfig with sensible defaults.
func DefaultSocketConfig() SocketConfig {
	return SocketConfig{
		FrameSize:          defaultFrameSize,
		FrameCount:         defaultFrameCount,
		FillRingSize:       defaultFillRingSize,
		CompletionRingSize: defaultCompletionRingSize,
		RXRingSize:         defaultRXRingSize,
		TXRingSize:         defaultTXRingSize,
		TXFrameReserve:     defaultTXFrameReserve,
		BindFlags:          defaultBindFlags,
	}
}

// Validate checks that the configuration values are valid.
func (c SocketConfig) Validate() error {
	if c.IfIndex <= 0 {
		return fmt.Errorf("af_xdp socket config: invalid ifindex %d", c.IfIndex)
	}
	if c.FrameSize != 2048 && c.FrameSize != 4096 {
		return fmt.Errorf("af_xdp socket config: invalid frame size %d, must be 2048 or 4096", c.FrameSize)
	}
	if err := checkPowerOf2(c.FrameCount, "frame count"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.FillRingSize, "fill ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.CompletionRingSize, "completion ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.RXRingSize, "rx ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.TXRingSize, "tx ring size"); err != nil {
		return err
	}
	if c.TXFrameReserve == 0 {
		return fmt.Errorf("af_xdp socket config: tx frame reserve must be greater than 0")
	}
	if c.FillRingSize+c.TXFrameReserve > c.FrameCount {
		return fmt.Errorf("af_xdp socket config: fill ring size %d plus tx frame reserve %d exceeds frame count %d", c.FillRingSize, c.TXFrameReserve, c.FrameCount)
	}
	return nil
}

func checkPowerOf2(n uint32, name string) error {
	if n == 0 || bits.OnesCount32(n) != 1 {
		return fmt.Errorf("af_xdp socket config: invalid %s %d, must be a power of 2", name, n)
	}
	return nil
}
