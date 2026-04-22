package xsk

import (
	"fmt"
	"math/bits"
)

const (
	defaultFrameSize = 4096
	defaultFrameNum  = 4096
	defaultFillSize  = 2048
	defaultCompSize  = 2048
	defaultRxSize    = 2048
	defaultTxSize    = 2048
)

// Config holds the configuration for creating AF_XDP sockets.
type Config struct {
	IfIndex   int
	BindFlags uint16 // e.g. XDP_COPY, XDP_USE_NEED_WAKEUP

	FrameSize uint32 // 2048 or 4096, default 4096
	FrameNum  uint32 // power of 2, default 4096
	FillSize  uint32 // power of 2, default 2048
	CompSize  uint32 // power of 2, default 2048
	RxSize    uint32 // power of 2, default 2048
	TxSize    uint32 // power of 2, default 2048
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		FrameSize: defaultFrameSize,
		FrameNum:  defaultFrameNum,
		FillSize:  defaultFillSize,
		CompSize:  defaultCompSize,
		RxSize:    defaultRxSize,
		TxSize:    defaultTxSize,
	}
}

// Validate checks that the configuration values are valid.
func (c Config) Validate() error {
	if c.IfIndex <= 0 {
		return fmt.Errorf("xsk backend config: invalid ifindex %d", c.IfIndex)
	}
	if c.FrameSize != 2048 && c.FrameSize != 4096 {
		return fmt.Errorf("xsk backend config: invalid frame size %d, must be 2048 or 4096", c.FrameSize)
	}
	if err := checkPowerOf2(c.FrameNum, "frame count"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.FillSize, "fill ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.CompSize, "completion ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.RxSize, "rx ring size"); err != nil {
		return err
	}
	if err := checkPowerOf2(c.TxSize, "tx ring size"); err != nil {
		return err
	}
	return nil
}

func checkPowerOf2(n uint32, name string) error {
	if n == 0 || bits.OnesCount32(n) != 1 {
		return fmt.Errorf("xsk backend config: invalid %s %d, must be a power of 2", name, n)
	}
	return nil
}
