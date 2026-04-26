package dataplane

import (
	"fmt"
	"strings"
)

func (r *Runtime) writeXDPResponseConfig(opts XDPResponseOptions) error {
	cfg := siderspTxConfig{
		TcpResetMode:           xdpResponseMode(opts.EgressIfIndex),
		TcpResetEgressIfindex:  uint32(opts.EgressIfIndex),
		TcpResetVlanMode:       xdpResponseVLANMode(opts.VLANMode),
		TcpResetFailureVerdict: xdpResponseFailureVerdict(opts.FailureVerdict),
	}
	if err := r.objs.TxConfigMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("write tx_config_map: %w", err)
	}
	return nil
}

func xdpResponseMode(egressIfIndex int) uint32 {
	if egressIfIndex > 0 {
		return tcpResetTXModeRedirect
	}
	return tcpResetTXModeTX
}

func xdpResponseVLANMode(raw string) uint32 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "access":
		return tcpResetVLANAccess
	default:
		return tcpResetVLANPreserve
	}
}

func xdpResponseFailureVerdict(raw string) uint32 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "drop":
		return tcpResetFailureDrop
	default:
		return tcpResetFailurePass
	}
}
