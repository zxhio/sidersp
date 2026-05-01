package response

import (
	"fmt"
	"net"
	"strings"

	"sidersp/internal/config"
)

const defaultResultBufferSize = 1024

type Options struct {
	Enabled          bool
	IfIndex          int
	ResultBufferSize int
	HardwareAddr     net.HardwareAddr
	EgressInterface  string
}

func NewOptions(dataplaneCfg config.DataplaneConfig, egressCfg config.EgressConfig, responseCfg config.ResponseConfig, xskCfg config.XSKConfig) (Options, error) {
	interfaceName := strings.TrimSpace(dataplaneCfg.Interface)
	opts := Options{
		Enabled:         xskCfg.Enabled,
		EgressInterface: strings.TrimSpace(egressCfg.Interface),
	}
	if !opts.Enabled {
		return opts, nil
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return Options{}, fmt.Errorf("lookup response interface: %w", err)
	}
	txIface := iface
	if opts.EgressInterface != "" {
		txIface, err = net.InterfaceByName(opts.EgressInterface)
		if err != nil {
			return Options{}, fmt.Errorf("lookup response tx interface: %w", err)
		}
	}
	opts.IfIndex = iface.Index
	opts.ResultBufferSize = normalizedResultBufferSize(responseCfg.ResultBufferSize)

	hardwareAddr, err := resolveTXHardwareAddr(*txIface)
	if err != nil {
		return Options{}, err
	}
	opts.HardwareAddr = hardwareAddr

	return normalizeOptions(opts), nil
}

func resolveTXHardwareAddr(txIface net.Interface) (net.HardwareAddr, error) {
	if len(txIface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("response tx interface %q must have a 6-byte ethernet hardware address", txIface.Name)
	}
	return append(net.HardwareAddr(nil), txIface.HardwareAddr...), nil
}

func normalizedResultBufferSize(raw int) int {
	if raw <= 0 {
		return defaultResultBufferSize
	}
	return raw
}

func normalizeOptions(opts Options) Options {
	if opts.ResultBufferSize <= 0 {
		opts.ResultBufferSize = defaultResultBufferSize
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.IfIndex <= 0 {
		return fmt.Errorf("create response runtime: ifindex must be > 0")
	}
	if opts.ResultBufferSize <= 0 {
		return fmt.Errorf("create response runtime: result buffer size must be > 0")
	}
	return nil
}
