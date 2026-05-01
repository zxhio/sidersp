package dataplane

import (
	"fmt"
	"net"
	"strings"

	"sidersp/internal/config"
	"sidersp/internal/xsk"
)

func NewOptions(dataplaneCfg config.DataplaneConfig, egressCfg config.EgressConfig, xskCfg config.XSKConfig) (Options, error) {
	interfaceName := strings.TrimSpace(dataplaneCfg.Interface)
	ingressVerdict, err := normalizedIngressVerdict(dataplaneCfg.IngressVerdict)
	if err != nil {
		return Options{}, err
	}
	xdpResponse, err := newXDPResponseOptions(egressCfg)
	if err != nil {
		return Options{}, err
	}
	xskOpts, err := xsk.NewOptions(dataplaneCfg, xskCfg)
	if err != nil {
		return Options{}, err
	}

	return Options{
		Interface:        interfaceName,
		AttachMode:       dataplaneCfg.AttachMode,
		CombinedChannels: normalizedCombinedChannels(dataplaneCfg.CombinedChannels),
		IngressVerdict:   ingressVerdict,
		XDPResponse:      xdpResponse,
		XSK:              xskOpts,
	}, nil
}

func normalizedCombinedChannels(raw int) int {
	if raw <= 0 {
		return 0
	}
	return raw
}

func normalizedIngressVerdict(raw string) (string, error) {
	verdict := strings.ToLower(strings.TrimSpace(raw))
	if verdict == "" {
		verdict = "pass"
	}
	switch verdict {
	case "pass", "drop":
		return verdict, nil
	default:
		return "", fmt.Errorf("dataplane.ingress_verdict %q is not valid", raw)
	}
}

func newXDPResponseOptions(cfg config.EgressConfig) (XDPResponseOptions, error) {
	vlanMode, err := normalizedVLANMode(cfg.VLANMode)
	if err != nil {
		return XDPResponseOptions{}, err
	}
	failureVerdict, err := normalizedFailureVerdict(cfg.FailureVerdict)
	if err != nil {
		return XDPResponseOptions{}, err
	}

	var egressIfIndex int
	if ifaceName := strings.TrimSpace(cfg.Interface); ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return XDPResponseOptions{}, fmt.Errorf("lookup egress interface %s: %w", ifaceName, err)
		}
		egressIfIndex = iface.Index
	}

	return XDPResponseOptions{
		EgressIfIndex:  egressIfIndex,
		VLANMode:       vlanMode,
		FailureVerdict: failureVerdict,
	}, nil
}

func normalizedVLANMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		mode = "preserve"
	}
	switch mode {
	case "preserve", "access":
		return mode, nil
	default:
		return "", fmt.Errorf("egress: vlan_mode %q is not valid", raw)
	}
}

func normalizedFailureVerdict(raw string) (string, error) {
	verdict := strings.ToLower(strings.TrimSpace(raw))
	if verdict == "" {
		verdict = "pass"
	}
	switch verdict {
	case "pass", "drop":
		return verdict, nil
	default:
		return "", fmt.Errorf("egress: failure_verdict %q is not valid", raw)
	}
}
