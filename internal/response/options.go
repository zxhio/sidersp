package response

import (
	"fmt"
	"net"
	"strings"

	"sidersp/internal/config"
	"sidersp/internal/response/afxdp"
)

const defaultResultBufferSize = 1024

type Options struct {
	Enabled          bool
	IfIndex          int
	Queues           []int
	ResultBufferSize int
	HardwareAddr     net.HardwareAddr
	TCPSeq           uint32
	EgressInterface  string
	Registrar        XSKRegistrar
	NewXSK           NewXSKFunc
}

func NewOptions(dataplaneCfg config.DataplaneConfig, egressCfg config.EgressConfig, responseCfg config.ResponseConfig, registrar XSKRegistrar) (Options, error) {
	interfaceName := strings.TrimSpace(dataplaneCfg.Interface)
	opts := Options{
		Enabled:         responseCfg.Runtime.Enabled,
		TCPSeq:          responseCfg.Actions.TCPSynAck.TCPSeq,
		EgressInterface: strings.TrimSpace(egressCfg.Interface),
		Registrar:       registrar,
	}
	if !opts.Enabled {
		return opts, nil
	}
	if registrar == nil {
		return Options{}, fmt.Errorf("create response options: registrar is required")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return Options{}, fmt.Errorf("lookup response interface: %w", err)
	}
	opts.IfIndex = iface.Index
	opts.Queues = normalizedWorkerQueues(responseCfg.Runtime.Queues, dataplaneCfg.CombinedChannels)
	opts.ResultBufferSize = normalizedResultBufferSize(responseCfg.Runtime.ResultBufferSize)

	if rawHWAddr := strings.TrimSpace(responseCfg.Actions.ARPReply.HardwareAddr); rawHWAddr != "" {
		hardwareAddr, err := net.ParseMAC(rawHWAddr)
		if err != nil {
			return Options{}, fmt.Errorf("parse response hardware address: %w", err)
		}
		opts.HardwareAddr = hardwareAddr
	}

	afxdpCfg := newAFXDPConfig(responseCfg.Runtime.AFXDP, iface.Index)
	if err := afxdpCfg.Validate(); err != nil {
		return Options{}, err
	}
	opts.NewXSK = func(queueID int) (XSKSocket, error) {
		return afxdp.NewSocket(afxdpCfg, queueID)
	}

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

func normalizedResultBufferSize(raw int) int {
	if raw <= 0 {
		return defaultResultBufferSize
	}
	return raw
}

func normalizeOptions(opts Options) Options {
	if len(opts.Queues) == 0 {
		opts.Queues = []int{0}
	}
	if opts.ResultBufferSize <= 0 {
		opts.ResultBufferSize = defaultResultBufferSize
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.Registrar == nil {
		return fmt.Errorf("create response runtime: registrar is required")
	}
	if opts.NewXSK == nil {
		return fmt.Errorf("create response runtime: xsk socket is required")
	}
	if opts.IfIndex <= 0 {
		return fmt.Errorf("create response runtime: ifindex must be > 0")
	}
	if len(opts.Queues) == 0 {
		return fmt.Errorf("create response runtime: at least one queue is required")
	}
	if opts.ResultBufferSize <= 0 {
		return fmt.Errorf("create response runtime: result buffer size must be > 0")
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
