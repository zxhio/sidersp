package controlplane

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"sidersp/internal/rule"
)

var allowedActions = map[string]struct{}{
	"none":            {},
	"alert":           {},
	"tcp_reset":       {},
	"icmp_echo_reply": {},
	"arp_reply":       {},
	"tcp_syn_ack":     {},
}

var allowedProtocols = map[string]struct{}{
	"tcp":  {},
	"udp":  {},
	"icmp": {},
	"arp":  {},
}

var ErrRuleValidation = errors.New("rule validation failed")

func LoadRules(path string) (rule.RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return rule.RuleSet{}, fmt.Errorf("read rules file: %w", err)
	}

	var set rule.RuleSet
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&set); err != nil {
		return rule.RuleSet{}, fmt.Errorf("decode rules file: %w", err)
	}

	if err := normalizeRuleSet(&set); err != nil {
		return rule.RuleSet{}, err
	}

	return set, nil
}

func SaveRules(path string, set rule.RuleSet) error {
	next := cloneRuleSet(set)
	if err := normalizeRuleSet(&next); err != nil {
		return err
	}

	data, err := yaml.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode rules file: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create rules directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write rules file: %w", err)
	}

	return nil
}

func normalizeRuleSet(s *rule.RuleSet) error {
	seenIDs := make(map[int]struct{}, len(s.Rules))
	for i := range s.Rules {
		if err := normalizeRule(&s.Rules[i]); err != nil {
			return fmt.Errorf("%w: rule %d: %v", ErrRuleValidation, i, err)
		}
		if _, ok := seenIDs[s.Rules[i].ID]; ok {
			return fmt.Errorf("%w: duplicate id %d", ErrRuleValidation, s.Rules[i].ID)
		}
		seenIDs[s.Rules[i].ID] = struct{}{}
	}

	slices.SortStableFunc(s.Rules, func(a, b rule.Rule) int {
		return cmp.Compare(a.Priority, b.Priority)
	})

	return nil
}

func enabledRuleSet(set rule.RuleSet) rule.RuleSet {
	enabled := rule.RuleSet{
		Rules: make([]rule.Rule, 0, len(set.Rules)),
	}

	for _, item := range set.Rules {
		if !item.Enabled {
			continue
		}
		enabled.Rules = append(enabled.Rules, item)
	}

	return enabled
}

func normalizeRule(r *rule.Rule) error {
	switch {
	case r.ID == 0:
		return fmt.Errorf("id is required")
	case strings.TrimSpace(r.Name) == "":
		return fmt.Errorf("name is required")
	case r.Priority < 0:
		return fmt.Errorf("priority must be >= 0")
	}

	vlans, err := normalizeVLANs(r.Match.VLANs)
	if err != nil {
		return fmt.Errorf("match.vlans: %w", err)
	}
	srcPrefixes, err := normalizePrefixes(r.Match.SrcPrefixes)
	if err != nil {
		return fmt.Errorf("match.src_prefixes: %w", err)
	}
	dstPrefixes, err := normalizePrefixes(r.Match.DstPrefixes)
	if err != nil {
		return fmt.Errorf("match.dst_prefixes: %w", err)
	}
	srcPorts, err := normalizePorts(r.Match.SrcPorts)
	if err != nil {
		return fmt.Errorf("match.src_ports: %w", err)
	}
	dstPorts, err := normalizePorts(r.Match.DstPorts)
	if err != nil {
		return fmt.Errorf("match.dst_ports: %w", err)
	}

	protocol := strings.ToLower(strings.TrimSpace(r.Match.Protocol))
	if protocol != "" {
		if _, ok := allowedProtocols[protocol]; !ok {
			return fmt.Errorf("match.protocol %q is not allowed", r.Match.Protocol)
		}
	}
	if err := validateTCPFlags(r.Match.TCPFlags); err != nil {
		return fmt.Errorf("match.tcp_flags: %w", err)
	}
	if r.Match.ICMP != nil {
		icmpType := strings.ToLower(strings.TrimSpace(r.Match.ICMP.Type))
		switch icmpType {
		case "echo_request", "echo_reply":
			r.Match.ICMP.Type = icmpType
		default:
			return fmt.Errorf("match.icmp.type %q is not allowed", r.Match.ICMP.Type)
		}
	}
	if r.Match.ARP != nil {
		operation := strings.ToLower(strings.TrimSpace(r.Match.ARP.Operation))
		switch operation {
		case "request", "reply":
			r.Match.ARP.Operation = operation
		default:
			return fmt.Errorf("match.arp.operation %q is not allowed", r.Match.ARP.Operation)
		}
	}

	action := strings.ToLower(strings.TrimSpace(r.Response.Action))
	if action == "" {
		return fmt.Errorf("response.action is required")
	}
	if _, ok := allowedActions[action]; !ok {
		return fmt.Errorf("response.action %q is not allowed", action)
	}
	r.Match.Protocol = protocol
	if err := validateActionMatch(action, r); err != nil {
		return err
	}

	r.Match.VLANs = vlans
	r.Match.SrcPrefixes = srcPrefixes
	r.Match.DstPrefixes = dstPrefixes
	r.Match.SrcPorts = srcPorts
	r.Match.DstPorts = dstPorts
	r.Response.Action = action

	return nil
}

func validateActionMatch(action string, r *rule.Rule) error {
	switch action {
	case "icmp_echo_reply":
		if r.Match.Protocol != "icmp" {
			return fmt.Errorf("response.action icmp_echo_reply requires match.protocol icmp")
		}
		if r.Match.ICMP == nil || r.Match.ICMP.Type != "echo_request" {
			return fmt.Errorf("response.action icmp_echo_reply requires match.icmp.type echo_request")
		}
	case "arp_reply":
		if r.Match.Protocol != "arp" {
			return fmt.Errorf("response.action arp_reply requires match.protocol arp")
		}
		if r.Match.ARP == nil || r.Match.ARP.Operation != "request" {
			return fmt.Errorf("response.action arp_reply requires match.arp.operation request")
		}
	case "tcp_syn_ack":
		if r.Match.Protocol != "tcp" {
			return fmt.Errorf("response.action tcp_syn_ack requires match.protocol tcp")
		}
		if r.Match.TCPFlags.SYN == nil || !*r.Match.TCPFlags.SYN {
			return fmt.Errorf("response.action tcp_syn_ack requires match.tcp_flags.syn true")
		}
	}
	return nil
}

func validateTCPFlags(flags rule.TCPFlags) error {
	for _, item := range []struct {
		name  string
		value *bool
	}{
		{name: "syn", value: flags.SYN},
		{name: "ack", value: flags.ACK},
		{name: "rst", value: flags.RST},
		{name: "fin", value: flags.FIN},
		{name: "psh", value: flags.PSH},
	} {
		if item.value != nil && !*item.value {
			return fmt.Errorf("negative %s is not supported", item.name)
		}
	}
	return nil
}

func normalizePrefixes(prefixes []string) ([]string, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(prefixes))
	for _, raw := range prefixes {
		value := strings.TrimSpace(raw)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q", raw)
		}
		if !prefix.Addr().Is4() {
			return nil, fmt.Errorf("only IPv4 CIDRs are supported, got %q", raw)
		}
		normalized = append(normalized, prefix.Masked().String())
	}

	return normalized, nil
}

func normalizeVLANs(vlans []int) ([]int, error) {
	if len(vlans) == 0 {
		return nil, nil
	}

	normalized := make([]int, 0, len(vlans))
	for _, vlan := range vlans {
		if vlan < 0 || vlan > 4095 {
			return nil, fmt.Errorf("vlan %d out of range", vlan)
		}
		normalized = append(normalized, vlan)
	}

	return normalized, nil
}

func normalizePorts(ports []int) ([]int, error) {
	if len(ports) == 0 {
		return nil, nil
	}

	normalized := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range", port)
		}
		normalized = append(normalized, port)
	}

	return normalized, nil
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}

	return normalized
}
