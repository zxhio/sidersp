package response

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"sidersp/internal/rule"
)

const (
	dnsDefaultTTLSeconds = 60
	dnsMaxTTLSeconds     = 2147483647
	tcpMaxSeqValue       = 4294967295
)

type DNSResponseConfig struct {
	RCode     uint8
	TTL       uint32
	AnswersV4 []netip.Addr
	AnswersV6 []netip.Addr
}

type ARPReplyConfig struct {
	HardwareAddr net.HardwareAddr
	SenderIPv4   netip.Addr
}

type TCPSynAckConfig struct {
	TCPSeq uint32
}

type integerRuleParam interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

func (c ARPReplyConfig) HasHardwareAddr() bool {
	return len(c.HardwareAddr) == 6
}

func (c ARPReplyConfig) HasSenderIPv4() bool {
	return c.SenderIPv4.IsValid()
}

func (c ARPReplyConfig) Empty() bool {
	return !c.HasHardwareAddr() && !c.HasSenderIPv4()
}

type RuleConfigStore struct {
	mu         sync.RWMutex
	dnsRules   map[uint32]DNSResponseConfig
	arpReplies map[uint32]ARPReplyConfig
	tcpSynAcks map[uint32]TCPSynAckConfig
}

func NewRuleConfigStore() *RuleConfigStore {
	return &RuleConfigStore{}
}

func (s *RuleConfigStore) ReplaceRules(set rule.RuleSet) error {
	if s == nil {
		return fmt.Errorf("replace response rules: nil rule config store")
	}

	nextDNS := make(map[uint32]DNSResponseConfig)
	nextARP := make(map[uint32]ARPReplyConfig)
	nextTCP := make(map[uint32]TCPSynAckConfig)
	for _, item := range set.Rules {
		switch strings.ToLower(strings.TrimSpace(item.Response.Action)) {
		case "dns_sinkhole":
			config, err := parseDNSSinkholeRuleConfig(item)
			if err != nil {
				return fmt.Errorf("replace response rules: rule %d: %w", item.ID, err)
			}
			nextDNS[uint32(item.ID)] = config
		case "dns_refused":
			config, err := parseDNSRefusedRuleConfig(item)
			if err != nil {
				return fmt.Errorf("replace response rules: rule %d: %w", item.ID, err)
			}
			nextDNS[uint32(item.ID)] = config
		case "arp_reply":
			config, err := parseARPReplyRuleConfig(item)
			if err != nil {
				return fmt.Errorf("replace response rules: rule %d: %w", item.ID, err)
			}
			if !config.Empty() {
				nextARP[uint32(item.ID)] = config
			}
		case "tcp_syn_ack":
			config, err := parseTCPSynAckRuleConfig(item)
			if err != nil {
				return fmt.Errorf("replace response rules: rule %d: %w", item.ID, err)
			}
			nextTCP[uint32(item.ID)] = config
		}
	}

	s.mu.Lock()
	s.dnsRules = nextDNS
	s.arpReplies = nextARP
	s.tcpSynAcks = nextTCP
	s.mu.Unlock()
	return nil
}

func (s *RuleConfigStore) DNSResponseConfig(ruleID uint32) (DNSResponseConfig, bool) {
	if s == nil {
		return DNSResponseConfig{}, false
	}

	s.mu.RLock()
	config, ok := s.dnsRules[ruleID]
	s.mu.RUnlock()
	return config, ok
}

func (s *RuleConfigStore) ARPReplyConfig(ruleID uint32) (ARPReplyConfig, bool) {
	if s == nil {
		return ARPReplyConfig{}, false
	}

	s.mu.RLock()
	config, ok := s.arpReplies[ruleID]
	s.mu.RUnlock()
	return config, ok
}

func (s *RuleConfigStore) TCPSynAckConfig(ruleID uint32) (TCPSynAckConfig, bool) {
	if s == nil {
		return TCPSynAckConfig{}, false
	}

	s.mu.RLock()
	config, ok := s.tcpSynAcks[ruleID]
	s.mu.RUnlock()
	return config, ok
}

func parseDNSSinkholeRuleConfig(item rule.Rule) (DNSResponseConfig, error) {
	family, ok := item.Response.Params["family"].(string)
	if !ok {
		return DNSResponseConfig{}, fmt.Errorf("response.params.family must be one of ipv4, ipv6, dual")
	}

	ttl := uint32(dnsDefaultTTLSeconds)
	if rawTTL, ok := item.Response.Params["ttl"]; ok {
		value, ok := rawTTL.(int)
		if !ok || value < 0 || value > dnsMaxTTLSeconds {
			return DNSResponseConfig{}, fmt.Errorf("response.params.ttl must be an integer in range 0..2147483647")
		}
		ttl = uint32(value)
	}

	config := DNSResponseConfig{TTL: ttl}
	switch family {
	case "ipv4":
		answersV4, err := parseDNSAnswerList(item.Response.Params["answers_v4"], true)
		if err != nil {
			return DNSResponseConfig{}, err
		}
		config.AnswersV4 = answersV4
	case "ipv6":
		answersV6, err := parseDNSAnswerList(item.Response.Params["answers_v6"], false)
		if err != nil {
			return DNSResponseConfig{}, err
		}
		config.AnswersV6 = answersV6
	case "dual":
		answersV4, err := parseDNSAnswerList(item.Response.Params["answers_v4"], true)
		if err != nil {
			return DNSResponseConfig{}, err
		}
		answersV6, err := parseDNSAnswerList(item.Response.Params["answers_v6"], false)
		if err != nil {
			return DNSResponseConfig{}, err
		}
		config.AnswersV4 = answersV4
		config.AnswersV6 = answersV6
	default:
		return DNSResponseConfig{}, fmt.Errorf("response.params.family must be one of ipv4, ipv6, dual")
	}

	return config, nil
}

func parseDNSRefusedRuleConfig(item rule.Rule) (DNSResponseConfig, error) {
	raw, ok := item.Response.Params["rcode"].(string)
	if !ok {
		return DNSResponseConfig{}, fmt.Errorf("response.params.rcode must be one of refused, nxdomain, servfail")
	}

	rcode, err := parseDNSRCode(raw)
	if err != nil {
		return DNSResponseConfig{}, err
	}

	return DNSResponseConfig{RCode: rcode}, nil
}

func parseARPReplyRuleConfig(item rule.Rule) (ARPReplyConfig, error) {
	config := ARPReplyConfig{}
	if raw, ok := item.Response.Params["hardware_addr"]; ok {
		macValue, ok := raw.(string)
		if !ok {
			return ARPReplyConfig{}, fmt.Errorf("response.params.hardware_addr must be a 6-byte ethernet address string")
		}
		hardwareAddr, err := net.ParseMAC(strings.TrimSpace(macValue))
		if err != nil || len(hardwareAddr) != 6 {
			return ARPReplyConfig{}, fmt.Errorf("response.params.hardware_addr must be a 6-byte ethernet address string")
		}
		config.HardwareAddr = append(net.HardwareAddr(nil), hardwareAddr...)
	}
	if raw, ok := item.Response.Params["sender_ipv4"]; ok {
		ipValue, ok := raw.(string)
		if !ok {
			return ARPReplyConfig{}, fmt.Errorf("response.params.sender_ipv4 must be a single IPv4 address string")
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(ipValue))
		if err != nil || !addr.Is4() {
			return ARPReplyConfig{}, fmt.Errorf("response.params.sender_ipv4 must be a single IPv4 address string")
		}
		config.SenderIPv4 = addr
	}
	return config, nil
}

func parseTCPSynAckRuleConfig(item rule.Rule) (TCPSynAckConfig, error) {
	if _, ok := item.Response.Params["tcp_seq"]; !ok {
		return TCPSynAckConfig{TCPSeq: 1}, nil
	}

	value, err := parseUint32RuleParam(item.Response.Params["tcp_seq"], "response.params.tcp_seq")
	if err != nil {
		return TCPSynAckConfig{}, err
	}
	return TCPSynAckConfig{TCPSeq: value}, nil
}

func parseDNSAnswerList(value any, wantIPv4 bool) ([]netip.Addr, error) {
	items, ok := value.([]string)
	if !ok || len(items) == 0 {
		if wantIPv4 {
			return nil, fmt.Errorf("response.params.answers_v4 must be a non-empty IPv4 address list")
		}
		return nil, fmt.Errorf("response.params.answers_v6 must be a non-empty IPv6 address list")
	}

	answers := make([]netip.Addr, 0, len(items))
	for _, raw := range items {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			if wantIPv4 {
				return nil, fmt.Errorf("response.params.answers_v4 must be a non-empty IPv4 address list")
			}
			return nil, fmt.Errorf("response.params.answers_v6 must be a non-empty IPv6 address list")
		}
		if wantIPv4 && !addr.Is4() {
			return nil, fmt.Errorf("response.params.answers_v4 must be a non-empty IPv4 address list")
		}
		if !wantIPv4 && !addr.Is6() {
			return nil, fmt.Errorf("response.params.answers_v6 must be a non-empty IPv6 address list")
		}
		answers = append(answers, addr)
	}
	return answers, nil
}

func parseDNSRCode(raw string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "refused":
		return dnsRCodeRefused, nil
	case "nxdomain":
		return dnsRCodeNXDomain, nil
	case "servfail":
		return dnsRCodeServFail, nil
	default:
		return 0, fmt.Errorf("response.params.rcode must be one of refused, nxdomain, servfail")
	}
}

func parseUint32RuleParam(value any, field string) (uint32, error) {
	return normalizeAnyIntegerRuleParam(value, tcpMaxSeqValue, field+" must be an integer in range 0..4294967295", func(v uint64) uint32 {
		return uint32(v)
	})
}

func normalizeAnyIntegerRuleParam[R any](value any, max uint64, errorText string, cast func(uint64) R) (R, error) {
	switch v := value.(type) {
	case int:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case int8:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case int16:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case int32:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case int64:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case uint:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case uint8:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case uint16:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case uint32:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case uint64:
		return normalizeIntegerRuleParam(v, max, errorText, cast)
	case float64:
		if v < 0 || v > float64(max) || float64(uint64(v)) != v {
			var zero R
			return zero, fmt.Errorf("%s", errorText)
		}
		return normalizeIntegerRuleParam(uint64(v), max, errorText, cast)
	default:
		var zero R
		return zero, fmt.Errorf("%s", errorText)
	}
}

func normalizeIntegerRuleParam[T integerRuleParam, R any](value T, max uint64, errorText string, cast func(uint64) R) (R, error) {
	if value < 0 || uint64(value) > max {
		var zero R
		return zero, fmt.Errorf("%s", errorText)
	}
	return cast(uint64(value)), nil
}
