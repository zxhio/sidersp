package response

import (
	"strings"
	"testing"

	"sidersp/internal/rule"
)

func TestRuleConfigStoreReplaceRulesStoresDNSAndARPConfigs(t *testing.T) {
	t.Parallel()

	store := NewRuleConfigStore()
	err := store.ReplaceRules(rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID: 1001,
				Response: rule.RuleResponse{
					Action: "dns_sinkhole",
					Params: map[string]interface{}{
						"family":     "dual",
						"answers_v4": []string{"192.0.2.10"},
						"answers_v6": []string{"2001:db8::10"},
						"ttl":        300,
					},
				},
			},
			{
				ID: 1002,
				Response: rule.RuleResponse{
					Action: "dns_refused",
					Params: map[string]interface{}{
						"rcode": "servfail",
					},
				},
			},
			{
				ID: 1003,
				Response: rule.RuleResponse{
					Action: "arp_reply",
					Params: map[string]interface{}{
						"hardware_addr": "02:aa:bb:cc:dd:ee",
						"sender_ipv4":   "192.0.2.20",
					},
				},
			},
			{
				ID: 1004,
				Response: rule.RuleResponse{
					Action: "tcp_syn_ack",
					Params: map[string]interface{}{
						"tcp_seq": uint32(1000),
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	dnsSinkhole, ok := store.DNSResponseConfig(1001)
	if !ok || len(dnsSinkhole.AnswersV4) != 1 || len(dnsSinkhole.AnswersV6) != 1 || dnsSinkhole.TTL != 300 {
		t.Fatalf("DNSResponseConfig(1001) = %+v,%v, want dual sinkhole config", dnsSinkhole, ok)
	}
	dnsRefused, ok := store.DNSResponseConfig(1002)
	if !ok || dnsRefused.RCode != dnsRCodeServFail || len(dnsRefused.AnswersV4) != 0 || len(dnsRefused.AnswersV6) != 0 {
		t.Fatalf("DNSResponseConfig(1002) = %+v,%v, want servfail refused config", dnsRefused, ok)
	}
	arpReply, ok := store.ARPReplyConfig(1003)
	if !ok || !arpReply.HasHardwareAddr() || !arpReply.HasSenderIPv4() {
		t.Fatalf("ARPReplyConfig(1003) = %+v,%v, want arp override config", arpReply, ok)
	}
	tcpSynAck, ok := store.TCPSynAckConfig(1004)
	if !ok || tcpSynAck.TCPSeq != 1000 {
		t.Fatalf("TCPSynAckConfig(1004) = %+v,%v, want tcp_seq 1000", tcpSynAck, ok)
	}
	if _, ok := store.ARPReplyConfig(1001); ok {
		t.Fatal("ARPReplyConfig(1001) = true, want false")
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
					Params: map[string]interface{}{
						"family":     "ipv4",
						"answers_v4": []string{"192.0.2.10"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	config, ok := store.DNSResponseConfig(1001)
	if !ok || config.TTL != dnsDefaultTTLSeconds {
		t.Fatalf("DNSResponseConfig(1001) = %+v,%v, want default ttl %d", config, ok, dnsDefaultTTLSeconds)
	}
}

func TestRuleConfigStoreReplaceRulesDefaultsTCPSynAckSeq(t *testing.T) {
	t.Parallel()

	store := NewRuleConfigStore()
	err := store.ReplaceRules(rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID: 1001,
				Response: rule.RuleResponse{
					Action: "tcp_syn_ack",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	config, ok := store.TCPSynAckConfig(1001)
	if !ok || config.TCPSeq != 1 {
		t.Fatalf("TCPSynAckConfig(1001) = %+v,%v, want default tcp_seq 1", config, ok)
	}
}

func TestRuleConfigStoreReplaceRulesRejectsInvalidDNSSinkholeAnswers(t *testing.T) {
	t.Parallel()

	store := NewRuleConfigStore()
	err := store.ReplaceRules(rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID: 1001,
				Response: rule.RuleResponse{
					Action: "dns_sinkhole",
					Params: map[string]interface{}{
						"family":     "ipv4",
						"answers_v4": []string{"bad-ip"},
					},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("ReplaceRules() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "response.params.answers_v4") {
		t.Fatalf("ReplaceRules() error = %q, want answers_v4 validation error", err)
	}
}
