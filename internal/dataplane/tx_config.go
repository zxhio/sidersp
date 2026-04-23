package dataplane

import (
	"fmt"
	"strings"
)

func (r *Runtime) writeTXConfig(opts TCPResetTXOptions) error {
	cfg := siderspTxConfig{
		TcpResetMode:           tcpResetXDPMode(opts.EgressIfIndex),
		TcpResetEgressIfindex:  uint32(opts.EgressIfIndex),
		TcpResetVlanMode:       tcpResetVLANMode(opts.VLANMode),
		TcpResetFailureVerdict: tcpResetFailureVerdict(opts.FailureVerdict),
	}
	if err := r.objs.TxConfigMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("write tx_config_map: %w", err)
	}
	return nil
}

func tcpResetXDPMode(egressIfIndex int) uint32 {
	if egressIfIndex > 0 {
		return tcpResetTXModeRedirect
	}
	return tcpResetTXModeTX
}

func tcpResetVLANMode(raw string) uint32 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "access":
		return tcpResetVLANAccess
	default:
		return tcpResetVLANPreserve
	}
}

func tcpResetFailureVerdict(raw string) uint32 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "drop":
		return tcpResetFailureDrop
	default:
		return tcpResetFailurePass
	}
}
