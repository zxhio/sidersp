package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sidersp/internal/rule"
)

func TestLoadRules(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1003
    name: disabled
    enabled: false
    priority: 50
    match:
      protocol: tcp
      vlans: [300]
      src_prefixes: ["10.10.0.0/16"]
      dst_prefixes: ["192.168.3.0/24"]
      src_ports: [34567]
      dst_ports: [443]
      tcp_flags:
        syn: true
    response:
      action: tcp_reset
  - id: 1002
    name: later
    enabled: true
    priority: 200
    match:
      protocol: tcp
      vlans: [200]
      src_prefixes: ["10.0.0.1/8"]
      dst_prefixes: ["192.168.1.0/24"]
      src_ports: [12345]
      dst_ports: [8080]
      tcp_flags:
        syn: true
    response:
      action: tcp_reset
  - id: 1001
    name: first
    enabled: true
    priority: 100
    match:
      protocol: tcp
      vlans: [100]
      src_prefixes: ["10.0.0.0/8"]
      dst_prefixes: ["192.168.2.0/24"]
      src_ports: [23456]
      dst_ports: [80]
      tcp_flags:
        syn: true
    response:
      action: tcp_reset
`)

	set, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}

	if len(set.Rules) != 3 {
		t.Fatalf("len(Rules) = %d, want %d", len(set.Rules), 3)
	}

	if set.Rules[0].ID != 1003 {
		t.Fatalf("first rule id = %d, want %d", set.Rules[0].ID, 1003)
	}

	if got := set.Rules[2].Match.SrcPrefixes[0]; got != "10.0.0.0/8" {
		t.Fatalf("normalized src prefix = %q, want %q", got, "10.0.0.0/8")
	}

	if got := set.Rules[2].Response.Action; got != "tcp_reset" {
		t.Fatalf("normalized action = %q, want %q", got, "tcp_reset")
	}

	if set.Rules[2].Match.TCPFlags.SYN == nil || !*set.Rules[2].Match.TCPFlags.SYN {
		t.Fatal("normalized tcp_flags.syn = nil/false, want true")
	}

	if set.Rules[0].Enabled {
		t.Fatal("first rule enabled = true, want false")
	}
}

func TestLoadRulesAssignsMissingID(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - name: auto-id
    enabled: true
    priority: 100
    response:
      action: tcp_reset
`)

	set, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if len(set.Rules) != 1 {
		t.Fatalf("len(Rules) = %d, want 1", len(set.Rules))
	}
	if set.Rules[0].ID != 1 {
		t.Fatalf("assigned rule id = %d, want 1", set.Rules[0].ID)
	}
}

func TestLoadRulesAssignsMissingIDsAfterExistingMax(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1004
    name: existing
    enabled: true
    priority: 100
    response:
      action: tcp_reset
  - name: auto-one
    enabled: true
    priority: 110
    response:
      action: tcp_reset
  - id: 1009
    name: existing-max
    enabled: true
    priority: 120
    response:
      action: tcp_reset
  - name: auto-two
    enabled: true
    priority: 130
    response:
      action: tcp_reset
`)

	set, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if len(set.Rules) != 4 {
		t.Fatalf("len(Rules) = %d, want 4", len(set.Rules))
	}
	if set.Rules[1].ID != 1010 {
		t.Fatalf("auto-one id = %d, want 1010", set.Rules[1].ID)
	}
	if set.Rules[3].ID != 1011 {
		t.Fatalf("auto-two id = %d, want 1011", set.Rules[3].ID)
	}
}

func TestLoadRulesValidationError(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1001
    name: bad
    enabled: true
    priority: 100
    match:
      vlans: [100]
      src_prefixes: ["10.0.0.0/33"]
      dst_prefixes: ["192.168.1.0/24"]
      src_ports: [12345]
      dst_ports: [70000]
      tcp_flags:
        syn: true
    response:
      action: DROP
`)

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("LoadRules() error = nil, want validation error")
	}

	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Fatalf("LoadRules() error = %q, want CIDR validation error", err)
	}
}

func TestLoadRulesRejectsInvalidVLAN(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1001
    name: bad-vlan
    enabled: true
    priority: 100
    match:
      vlans: [4096]
      src_prefixes: ["10.0.0.0/8"]
      dst_prefixes: ["192.168.1.0/24"]
      src_ports: [12345]
      dst_ports: [80]
      tcp_flags:
        syn: true
    response:
      action: tcp_reset
`)

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("LoadRules() error = nil, want VLAN validation error")
	}

	if !strings.Contains(err.Error(), "vlan 4096 out of range") {
		t.Fatalf("LoadRules() error = %q, want VLAN validation error", err)
	}
}

func TestLoadRulesRejectsEmptyAction(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1001
    name: missing-action
    enabled: true
    priority: 100
    match:
      vlans: [100]
      src_prefixes: ["10.0.0.0/8"]
      dst_prefixes: ["192.168.1.0/24"]
      src_ports: [12345]
      dst_ports: [80]
      tcp_flags:
        syn: true
    response:
      action: "   "
`)

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("LoadRules() error = nil, want action validation error")
	}

	if !strings.Contains(err.Error(), "response.action is required") {
		t.Fatalf("LoadRules() error = %q, want action required error", err)
	}
}

func TestLoadRulesRejectsIPv6Prefix(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1001
    name: ipv6-prefix
    enabled: true
    priority: 100
    match:
      src_prefixes: ["2001:db8::/32"]
    response:
      action: tcp_reset
`)

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("LoadRules() error = nil, want IPv4-only validation error")
	}

	if !strings.Contains(err.Error(), "only IPv4 CIDRs are supported") {
		t.Fatalf("LoadRules() error = %q, want IPv4-only validation error", err)
	}
}

func TestSaveRulesNormalizesAndSorts(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.yaml")
	err := SaveRules(path, rule.RuleSet{
		Rules: []rule.Rule{
			{
				ID:       2,
				Name:     "later",
				Enabled:  true,
				Priority: 20,
				Match:    rule.RuleMatch{Protocol: "tcp", TCPFlags: rule.TCPFlags{SYN: boolPtr(true)}},
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
			{
				ID:       1,
				Name:     "first",
				Enabled:  true,
				Priority: 10,
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
		},
	})
	if err != nil {
		t.Fatalf("SaveRules() error = %v", err)
	}

	set, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if set.Rules[0].ID != 1 {
		t.Fatalf("first rule id = %d, want 1", set.Rules[0].ID)
	}
	if got := set.Rules[1].Response.Action; got != "tcp_reset" {
		t.Fatalf("action = %q, want tcp_reset", got)
	}
}

func TestSaveRulesWritesAssignedIDs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.yaml")
	err := SaveRules(path, rule.RuleSet{
		Rules: []rule.Rule{
			{
				Name:     "auto-id",
				Enabled:  true,
				Priority: 10,
				Response: rule.RuleResponse{Action: "tcp_reset"},
			},
		},
	})
	if err != nil {
		t.Fatalf("SaveRules() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rules file: %v", err)
	}
	if !strings.Contains(string(data), "id: 1") {
		t.Fatalf("saved rules = %q, want assigned id", string(data))
	}
}

func TestLoadRulesSortsByPriorityThenID(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 20
    name: later-id
    enabled: true
    priority: 100
    response:
      action: tcp_reset
  - id: 10
    name: earlier-id
    enabled: true
    priority: 100
    response:
      action: tcp_reset
`)

	set, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if set.Rules[0].ID != 10 || set.Rules[1].ID != 20 {
		t.Fatalf("rule order ids = %d,%d, want 10,20", set.Rules[0].ID, set.Rules[1].ID)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func TestLoadRulesRejectsIncompatibleXSKActions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ruleYAML string
		want     string
	}{
		{
			name: "icmp echo reply requires icmp echo request",
			ruleYAML: `match:
      protocol: icmp
      icmp:
        type: echo_reply
    response:
      action: icmp_echo_reply`,
			want: "requires match.icmp.type echo_request",
		},
		{
			name: "arp reply requires arp request",
			ruleYAML: `match:
      protocol: arp
      arp:
        operation: reply
    response:
      action: arp_reply`,
			want: "requires match.arp.operation request",
		},
		{
			name: "tcp syn ack requires tcp syn",
			ruleYAML: `match:
      protocol: tcp
      tcp_flags:
        ack: true
    response:
      action: tcp_syn_ack`,
			want: "requires match.tcp_flags.syn true",
		},
		{
			name: "tcp syn ack requires tcp protocol",
			ruleYAML: `match:
      protocol: udp
    response:
      action: tcp_syn_ack`,
			want: "requires match.protocol tcp",
		},
		{
			name: "icmp port unreachable requires udp protocol",
			ruleYAML: `match:
      protocol: tcp
    response:
      action: icmp_port_unreachable`,
			want: "requires match.protocol udp",
		},
		{
			name: "udp echo reply requires udp protocol",
			ruleYAML: `match:
      protocol: icmp
    response:
      action: udp_echo_reply`,
			want: "requires match.protocol udp",
		},
		{
			name: "dns refused requires udp protocol",
			ruleYAML: `match:
      protocol: arp
    response:
      action: dns_refused`,
			want: "requires match.protocol udp",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeRulesFile(t, `rules:
  - id: 1001
    name: bad
    enabled: true
    priority: 100
    `+tc.ruleYAML+`
`)

			_, err := LoadRules(path)
			if err == nil {
				t.Fatal("LoadRules() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadRules() error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadRulesAcceptsCompatibleXSKActions(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1001
    name: icmp
    enabled: true
    priority: 100
    match:
      protocol: icmp
      icmp:
        type: echo_request
    response:
      action: icmp_echo_reply
  - id: 1002
    name: arp
    enabled: true
    priority: 110
    match:
      protocol: arp
      arp:
        operation: request
    response:
      action: arp_reply
  - id: 1003
    name: syn
    enabled: true
    priority: 120
    match:
      protocol: tcp
      tcp_flags:
        syn: true
    response:
      action: tcp_syn_ack
  - id: 1004
    name: icmp-port-unreachable
    enabled: true
    priority: 130
    match:
      protocol: udp
      dst_ports: [9999]
    response:
      action: icmp_port_unreachable
  - id: 1005
    name: udp-echo
    enabled: true
    priority: 140
    match:
      protocol: udp
    response:
      action: udp_echo_reply
  - id: 1006
    name: dns-refused
    enabled: true
    priority: 150
    match:
      protocol: udp
      dst_ports: [53]
    response:
      action: dns_refused
`)

	set, err := LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if len(set.Rules) != 6 {
		t.Fatalf("len(Rules) = %d, want 6", len(set.Rules))
	}
}

func TestLoadRulesRejectsDuplicateID(t *testing.T) {
	t.Parallel()

	path := writeRulesFile(t, `rules:
  - id: 1001
    name: first
    enabled: true
    priority: 100
    response:
      action: tcp_reset
  - id: 1001
    name: duplicate
    enabled: true
    priority: 200
    response:
      action: tcp_reset
`)

	_, err := LoadRules(path)
	if err == nil {
		t.Fatal("LoadRules() error = nil, want duplicate id error")
	}

	if !strings.Contains(err.Error(), "duplicate id 1001") {
		t.Fatalf("LoadRules() error = %q, want duplicate id error", err)
	}
}

func writeRulesFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	return path
}
