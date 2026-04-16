package controlplane

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

var allowedActions = map[string]struct{}{
	"RST": {},
}

type RuleSet struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

type Rule struct {
	ID       int          `json:"id" yaml:"id"`
	Name     string       `json:"name" yaml:"name"`
	Enabled  bool         `json:"enabled" yaml:"enabled"`
	Priority int          `json:"priority" yaml:"priority"`
	Match    RuleMatch    `json:"match" yaml:"match"`
	Response RuleResponse `json:"response" yaml:"response"`
}

type RuleMatch struct {
	VLANs       []int    `json:"vlans" yaml:"vlans"`
	SrcPrefixes []string `json:"src_prefixes" yaml:"src_prefixes"`
	DstPrefixes []string `json:"dst_prefixes" yaml:"dst_prefixes"`
	SrcPorts    []int    `json:"src_ports" yaml:"src_ports"`
	DstPorts    []int    `json:"dst_ports" yaml:"dst_ports"`
	Features    []string `json:"features" yaml:"features"`
}

type RuleResponse struct {
	Action string `json:"action" yaml:"action"`
}

func LoadRules(path string) (RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, fmt.Errorf("read rules file: %w", err)
	}

	var set RuleSet
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&set); err != nil {
		return RuleSet{}, fmt.Errorf("decode rules file: %w", err)
	}

	if err := set.Normalize(); err != nil {
		return RuleSet{}, err
	}

	return set, nil
}

func (s *RuleSet) Normalize() error {
	normalized := make([]Rule, 0, len(s.Rules))
	for i := range s.Rules {
		if !s.Rules[i].Enabled {
			continue
		}
		if err := s.Rules[i].normalize(); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		normalized = append(normalized, s.Rules[i])
	}
	s.Rules = normalized

	slices.SortStableFunc(s.Rules, func(a, b Rule) int {
		return a.Priority - b.Priority
	})

	return nil
}

func (r *Rule) normalize() error {
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

	action := strings.TrimSpace(strings.ToUpper(r.Response.Action))
	if action == "" {
		return fmt.Errorf("response.action is required")
	}
	if _, ok := allowedActions[action]; !ok {
		return fmt.Errorf("response.action %q is not allowed", action)
	}

	r.Match.VLANs = vlans
	r.Match.SrcPrefixes = srcPrefixes
	r.Match.DstPrefixes = dstPrefixes
	r.Match.SrcPorts = srcPorts
	r.Match.DstPorts = dstPorts
	r.Match.Features = normalizeStrings(r.Match.Features)
	r.Response.Action = action

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
