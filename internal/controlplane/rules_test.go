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
      vlans: [300]
      src_prefixes: ["10.10.0.0/16"]
      dst_prefixes: ["192.168.3.0/24"]
      src_ports: [34567]
      dst_ports: [443]
      features: [HTTP_11]
    response:
      action: RST
  - id: 1002
    name: later
    enabled: true
    priority: 200
    match:
      vlans: [200]
      src_prefixes: ["10.0.0.1/8"]
      dst_prefixes: ["192.168.1.0/24"]
      src_ports: [12345]
      dst_ports: [8080]
      features: [" TCP_SYN ", HTTP_11]
    response:
      action: rst
  - id: 1001
    name: first
    enabled: true
    priority: 100
    match:
      vlans: [100]
      src_prefixes: ["10.0.0.0/8"]
      dst_prefixes: ["192.168.2.0/24"]
      src_ports: [23456]
      dst_ports: [80]
      features: [HTTP_METHOD]
    response:
      action: RST
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

	if got := set.Rules[2].Response.Action; got != "RST" {
		t.Fatalf("normalized action = %q, want %q", got, "RST")
	}

	if got := set.Rules[2].Match.Features[0]; got != "TCP_SYN" {
		t.Fatalf("normalized feature = %q, want %q", got, "TCP_SYN")
	}

	if set.Rules[0].Enabled {
		t.Fatal("first rule enabled = true, want false")
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
      features: [TCP_SYN]
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
      features: [TCP_SYN]
    response:
      action: RST
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
      features: [TCP_SYN]
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
      action: RST
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
				Match:    rule.RuleMatch{Features: []string{" HTTP_11 "}},
				Response: rule.RuleResponse{Action: "rst"},
			},
			{
				ID:       1,
				Name:     "first",
				Enabled:  true,
				Priority: 10,
				Response: rule.RuleResponse{Action: "RST"},
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
	if got := set.Rules[1].Response.Action; got != "RST" {
		t.Fatalf("action = %q, want RST", got)
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
      action: RST
  - id: 1001
    name: duplicate
    enabled: true
    priority: 200
    response:
      action: RST
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
