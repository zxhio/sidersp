package response

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"sidersp/internal/rule"
)

const (
	dnsDefaultTTLSeconds = 60
	dnsMaxTTLSeconds     = 2147483647
)

type DNSSinkholeConfig struct {
	Address netip.Addr
	TTL     uint32
}

type RuleConfigStore struct {
	mu           sync.RWMutex
	dnsSinkholes map[uint32]DNSSinkholeConfig
}

func NewRuleConfigStore() *RuleConfigStore {
	return &RuleConfigStore{}
}

func (s *RuleConfigStore) ReplaceRules(set rule.RuleSet) error {
	if s == nil {
		return fmt.Errorf("replace response rules: nil rule config store")
	}

	next := make(map[uint32]DNSSinkholeConfig)
	for _, item := range set.Rules {
		if strings.ToLower(strings.TrimSpace(item.Response.Action)) != "dns_sinkhole" {
			continue
		}

		config, err := parseDNSSinkholeRuleConfig(item)
		if err != nil {
			return fmt.Errorf("replace response rules: rule %d: %w", item.ID, err)
		}
		next[uint32(item.ID)] = config
	}

	s.mu.Lock()
	s.dnsSinkholes = next
	s.mu.Unlock()
	return nil
}

func (s *RuleConfigStore) DNSSinkholeConfig(ruleID uint32) (DNSSinkholeConfig, bool) {
	if s == nil {
		return DNSSinkholeConfig{}, false
	}

	s.mu.RLock()
	config, ok := s.dnsSinkholes[ruleID]
	s.mu.RUnlock()
	return config, ok
}

func parseDNSSinkholeRuleConfig(item rule.Rule) (DNSSinkholeConfig, error) {
	raw, ok := item.Response.Params["address"].(string)
	if !ok {
		return DNSSinkholeConfig{}, fmt.Errorf("response.params.address must be a single IPv4 address string")
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.Is4() {
		return DNSSinkholeConfig{}, fmt.Errorf("response.params.address must be a single IPv4 address string")
	}

	ttl := uint32(dnsDefaultTTLSeconds)
	if rawTTL, ok := item.Response.Params["ttl"]; ok {
		value, ok := rawTTL.(int)
		if !ok || value < 0 || value > dnsMaxTTLSeconds {
			return DNSSinkholeConfig{}, fmt.Errorf("response.params.ttl must be an integer in range 0..2147483647")
		}
		ttl = uint32(value)
	}

	return DNSSinkholeConfig{
		Address: addr,
		TTL:     ttl,
	}, nil
}
