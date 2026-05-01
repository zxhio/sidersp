package xsk

import (
	"fmt"
	"net"
	"strings"

	"sidersp/internal/config"
	"sidersp/internal/xsk/afxdp"
)

type Options struct {
	Enabled bool
	IfIndex int
	Queues  []int
	AFXDP   afxdp.SocketConfig
}

func NewOptions(dataplaneCfg config.DataplaneConfig, xskCfg config.XSKConfig) (Options, error) {
	interfaceName := strings.TrimSpace(dataplaneCfg.Interface)
	opts := Options{
		Enabled: xskCfg.Enabled,
	}
	if !opts.Enabled {
		return opts, nil
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return Options{}, fmt.Errorf("lookup xsk interface: %w", err)
	}
	opts.IfIndex = iface.Index
	opts.Queues = normalizedWorkerQueues(xskCfg.Queues, dataplaneCfg.CombinedChannels)

	afxdpCfg := newAFXDPConfig(xskCfg.AFXDP, iface.Index)
	if err := afxdpCfg.Validate(); err != nil {
		return Options{}, err
	}
	opts.AFXDP = afxdpCfg

	return normalizeOptions(opts), nil
}

func normalizedWorkerQueues(raw []int, defaultQueueCount int) []int {
	if len(raw) != 0 {
		return append([]int(nil), raw...)
	}
	if defaultQueueCount <= 0 {
		return []int{0}
	}

	queues := make([]int, defaultQueueCount)
	for i := 0; i < defaultQueueCount; i++ {
		queues[i] = i
	}
	return queues
}

func normalizeOptions(opts Options) Options {
	if len(opts.Queues) == 0 {
		opts.Queues = []int{0}
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.IfIndex <= 0 {
		return fmt.Errorf("create xsk runtime: ifindex must be > 0")
	}
	if len(opts.Queues) == 0 {
		return fmt.Errorf("create xsk runtime: at least one queue is required")
	}
	if err := opts.AFXDP.Validate(); err != nil {
		return err
	}
	return nil
}

func newAFXDPConfig(cfg config.AFXDPConfig, ifindex int) afxdp.SocketConfig {
	afxdpCfg := afxdp.DefaultSocketConfig()
	afxdpCfg.IfIndex = ifindex

	if v := cfg.FrameSize; v != 0 {
		afxdpCfg.FrameSize = v
	}
	if v := cfg.FrameCount; v != 0 {
		afxdpCfg.FrameCount = v
	}
	if v := cfg.FillRingSize; v != 0 {
		afxdpCfg.FillRingSize = v
	}
	if v := cfg.CompletionRingSize; v != 0 {
		afxdpCfg.CompletionRingSize = v
	}
	if v := cfg.RXRingSize; v != 0 {
		afxdpCfg.RXRingSize = v
	}
	if v := cfg.TXRingSize; v != 0 {
		afxdpCfg.TXRingSize = v
	}
	if v := cfg.TXFrameReserve; v != 0 {
		afxdpCfg.TXFrameReserve = v
	}

	return afxdpCfg
}
