package response

import (
	"strings"
	"testing"

	"sidersp/internal/rule"
)

func TestRuleConfigStoreReplaceRulesStoresDNSSinkholeConfig(t *testing.T) {
	t.Parallel()

	store := NewRuleConfigStore()
	err := store.ReplaceRules(rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID: 1001,
				Response: rule.RuleResponse{
					Action: "dns_sinkhole",
					Params: map[string]interface{}{"address": "192.0.2.10", "ttl": 300},
				},
			},
			{
				ID:       1002,
				Response: rule.RuleResponse{Action: "dns_refused"},
			},
		},
	})
	if err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	config, ok := store.DNSSinkholeConfig(1001)
	if !ok || config.Address.String() != "192.0.2.10" || config.TTL != 300 {
		t.Fatalf("DNSSinkholeConfig(1001) = %+v,%v, want 192.0.2.10/300/true", config, ok)
	}
	if _, ok := store.DNSSinkholeConfig(1002); ok {
		t.Fatal("DNSSinkholeConfig(1002) = true, want false")
	}
}

func TestRuleConfigStoreReplaceRulesDefaultsDNSSinkholeTTL(t *testing.T) {
	t.Parallel()

	store := NewRuleConfigStore()
	err := store.ReplaceRules(rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID: 1001,
				Response: rule.RuleResponse{
					Action: "dns_sinkhole",
					Params: map[string]interface{}{"address": "192.0.2.10"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	config, ok := store.DNSSinkholeConfig(1001)
	if !ok || config.TTL != dnsDefaultTTLSeconds {
		t.Fatalf("DNSSinkholeConfig(1001) = %+v,%v, want default ttl %d", config, ok, dnsDefaultTTLSeconds)
	}
}

func TestRuleConfigStoreReplaceRulesRejectsInvalidDNSSinkholeAddress(t *testing.T) {
	t.Parallel()

	store := NewRuleConfigStore()
	err := store.ReplaceRules(rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID: 1001,
				Response: rule.RuleResponse{
					Action: "dns_sinkhole",
					Params: map[string]interface{}{"address": "bad-ip"},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("ReplaceRules() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "response.params.address") {
		t.Fatalf("ReplaceRules() error = %q, want address validation error", err)
	}
}
