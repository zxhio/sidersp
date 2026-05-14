package runtime

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/types"
	"sidersp/internal/rule"
)

const maxDataplaneRuleSlots = 512

type dataplaneRuntimeEntry struct {
	ifindex int
	runtime DataplaneRuntime
}

func (r *DataplaneAttachmentRuntime) RulesetVersion(ctx context.Context) (uint64, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ruleset.Version, nil
}

func (r *DataplaneAttachmentRuntime) GetRuleset(ctx context.Context) (types.Ruleset, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneRuleset(r.ruleset), nil
}

func (r *DataplaneAttachmentRuntime) ValidateRuleset(ctx context.Context, ruleset types.Ruleset) error {
	_, err := newDataplaneRuleSet(ruleset)
	return err
}

func (r *DataplaneAttachmentRuntime) ReplaceRuleset(ctx context.Context, ruleset types.Ruleset) (types.Ruleset, error) {
	nextRules, err := newDataplaneRuleSet(ruleset)
	if err != nil {
		return types.Ruleset{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	previous := cloneRuleset(r.ruleset)
	previousRules, err := previousDataplaneRuleSet(previous)
	if err != nil {
		return types.Ruleset{}, err
	}
	entries := r.enabledDataplaneRuntimesLocked()

	if err := r.applyRulesetLocked(entries, nextRules, previousRules); err != nil {
		return types.Ruleset{}, err
	}

	r.ruleset = cloneRuleset(ruleset)
	logrus.WithFields(logrus.Fields{
		"version":     ruleset.Version,
		"rules":       len(ruleset.Rules),
		"attachments": len(entries),
	}).Info("Applied dataplane ruleset")
	return cloneRuleset(r.ruleset), nil
}

func (r *DataplaneAttachmentRuntime) ClearRuleset(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	previous := cloneRuleset(r.ruleset)
	previousRules, err := previousDataplaneRuleSet(previous)
	if err != nil {
		return err
	}
	entries := r.enabledDataplaneRuntimesLocked()

	if err := r.applyRulesetLocked(entries, rule.RuleSet{}, previousRules); err != nil {
		return err
	}

	r.ruleset = types.Ruleset{}
	logrus.WithField("attachments", len(entries)).Info("Cleared dataplane ruleset")
	return nil
}

func (r *DataplaneAttachmentRuntime) applyCurrentRulesetToRuntimeLocked(ifindex int, runtime DataplaneRuntime) error {
	if !hasStoredRuleset(r.ruleset) {
		return nil
	}
	rules, err := newDataplaneRuleSet(r.ruleset)
	if err != nil {
		return err
	}
	if err := runtime.ReplaceRules(rules); err != nil {
		return fmt.Errorf("apply current ruleset to attachment %d: %w", ifindex, err)
	}
	return nil
}

func (r *DataplaneAttachmentRuntime) applyRulesetLocked(entries []dataplaneRuntimeEntry, next rule.RuleSet, previous rule.RuleSet) error {
	applied := make([]dataplaneRuntimeEntry, 0, len(entries))
	for _, entry := range entries {
		if err := entry.runtime.ReplaceRules(cloneRuleSet(next)); err != nil {
			if rollbackErr := rollbackRuleset(applied, previous); rollbackErr != nil {
				logrus.WithError(rollbackErr).WithField("ifindex", entry.ifindex).Error("Fail to rollback dataplane ruleset")
				return fmt.Errorf("apply ruleset to attachment %d: %w; rollback failed: %w", entry.ifindex, err, rollbackErr)
			}
			return fmt.Errorf("apply ruleset to attachment %d: %w", entry.ifindex, err)
		}
		applied = append(applied, entry)
	}
	return nil
}

func rollbackRuleset(entries []dataplaneRuntimeEntry, previous rule.RuleSet) error {
	var joined error
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if err := entry.runtime.ReplaceRules(cloneRuleSet(previous)); err != nil {
			joined = errors.Join(joined, fmt.Errorf("rollback ruleset on attachment %d: %w", entry.ifindex, err))
		}
	}
	return joined
}

func (r *DataplaneAttachmentRuntime) enabledDataplaneRuntimesLocked() []dataplaneRuntimeEntry {
	entries := make([]dataplaneRuntimeEntry, 0, len(r.runtimes))
	for ifindex, runtime := range r.runtimes {
		attachment, ok := r.attachments[ifindex]
		if !ok || !attachment.Enabled || runtime == nil {
			continue
		}
		entries = append(entries, dataplaneRuntimeEntry{
			ifindex: ifindex,
			runtime: runtime,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ifindex < entries[j].ifindex
	})
	return entries
}

func previousDataplaneRuleSet(ruleset types.Ruleset) (rule.RuleSet, error) {
	if !hasStoredRuleset(ruleset) {
		return rule.RuleSet{}, nil
	}
	return newDataplaneRuleSet(ruleset)
}

func hasStoredRuleset(ruleset types.Ruleset) bool {
	return ruleset.Version != 0 || ruleset.Rules != nil
}

func newDataplaneRuleSet(ruleset types.Ruleset) (rule.RuleSet, error) {
	if ruleset.Version == 0 {
		return rule.RuleSet{}, types.NewValidationError("version must be greater than 0")
	}
	if ruleset.Rules == nil {
		return rule.RuleSet{}, types.NewValidationError("rules is required")
	}
	if len(ruleset.Rules) > maxDataplaneRuleSlots {
		return rule.RuleSet{}, types.NewValidationError("rules must not contain more than %d items", maxDataplaneRuleSlots)
	}

	out := rule.RuleSet{
		Rules: make([]rule.Rule, 0, len(ruleset.Rules)),
	}
	for i, item := range ruleset.Rules {
		next, err := newDataplaneRule(item, i)
		if err != nil {
			return rule.RuleSet{}, err
		}
		out.Rules = append(out.Rules, next)
	}
	return out, nil
}

func newDataplaneRule(item types.Rule, index int) (rule.Rule, error) {
	if item.RuleID == 0 {
		return rule.Rule{}, types.NewValidationError("rules[%d].rule_id is required", index)
	}
	if item.Priority < 0 {
		return rule.Rule{}, types.NewValidationError("rules[%d].priority must be greater than or equal to 0", index)
	}

	match, err := newDataplaneRuleMatch(item.Match, index)
	if err != nil {
		return rule.Rule{}, err
	}
	action, err := normalizeDataplaneAction(item, index)
	if err != nil {
		return rule.Rule{}, err
	}
	if err := validateDataplaneActionMatch(action, match, index); err != nil {
		return rule.Rule{}, err
	}

	return rule.Rule{
		ID:       int(item.RuleID),
		Enabled:  true,
		Priority: item.Priority,
		Match:    match,
		Response: rule.RuleResponse{
			Action: action,
			Params: cloneRuleParams(item.Response.Params),
		},
	}, nil
}

func newDataplaneRuleMatch(item types.RuleMatch, index int) (rule.RuleMatch, error) {
	protocol, err := normalizeDataplaneProtocol(item.Protocol, index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	vlans, err := normalizeDataplaneVLANs(item.VLANs, index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	srcPrefixes, err := normalizeDataplanePrefixes(item.SrcPrefixes, "src_prefixes", index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	dstPrefixes, err := normalizeDataplanePrefixes(item.DstPrefixes, "dst_prefixes", index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	srcPorts, err := normalizeDataplanePorts(item.SrcPorts, "src_ports", index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	dstPorts, err := normalizeDataplanePorts(item.DstPorts, "dst_ports", index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	if err := validateDataplaneTCPFlags(item.TCPFlags, index); err != nil {
		return rule.RuleMatch{}, err
	}
	icmp, err := newDataplaneICMPMatch(item.ICMP, index)
	if err != nil {
		return rule.RuleMatch{}, err
	}
	arp, err := newDataplaneARPMatch(item.ARP, index)
	if err != nil {
		return rule.RuleMatch{}, err
	}

	return rule.RuleMatch{
		Protocol:    protocol,
		VLANs:       vlans,
		SrcPrefixes: srcPrefixes,
		DstPrefixes: dstPrefixes,
		SrcPorts:    srcPorts,
		DstPorts:    dstPorts,
		TCPFlags: rule.TCPFlags{
			SYN: cloneBool(item.TCPFlags.SYN),
			ACK: cloneBool(item.TCPFlags.ACK),
			RST: cloneBool(item.TCPFlags.RST),
			FIN: cloneBool(item.TCPFlags.FIN),
			PSH: cloneBool(item.TCPFlags.PSH),
		},
		ICMP: icmp,
		ARP:  arp,
	}, nil
}

func normalizeDataplaneProtocol(raw string, index int) (string, error) {
	protocol := strings.ToLower(strings.TrimSpace(raw))
	switch protocol {
	case "", "tcp", "udp", "icmp", "arp":
		return protocol, nil
	default:
		return "", types.NewValidationError("rules[%d].match.protocol %q is not allowed", index, raw)
	}
}

func normalizeDataplaneVLANs(items []int, index int) ([]int, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		if item < 0 || item > 4095 {
			return nil, types.NewValidationError("rules[%d].match.vlans contains out of range vlan %d", index, item)
		}
		out = append(out, item)
	}
	return out, nil
}

func normalizeDataplanePrefixes(items []string, field string, index int) ([]string, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, types.NewValidationError("rules[%d].match.%s contains invalid CIDR %q", index, field, item)
		}
		if !prefix.Addr().Is4() {
			return nil, types.NewValidationError("rules[%d].match.%s only supports IPv4 CIDRs", index, field)
		}
		out = append(out, prefix.Masked().String())
	}
	return out, nil
}

func normalizeDataplanePorts(items []int, field string, index int) ([]int, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		if item < 1 || item > 65535 {
			return nil, types.NewValidationError("rules[%d].match.%s contains out of range port %d", index, field, item)
		}
		out = append(out, item)
	}
	return out, nil
}

func validateDataplaneTCPFlags(flags types.TCPFlags, index int) error {
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
			return types.NewValidationError("rules[%d].match.tcp_flags.%s false is not supported", index, item.name)
		}
	}
	return nil
}

func newDataplaneICMPMatch(item *types.ICMPMatch, index int) (*rule.ICMPMatch, error) {
	if item == nil {
		return nil, nil
	}
	icmpType := strings.ToLower(strings.TrimSpace(item.Type))
	switch icmpType {
	case "echo_request", "echo_reply":
		return &rule.ICMPMatch{Type: icmpType}, nil
	default:
		return nil, types.NewValidationError("rules[%d].match.icmp.type %q is not allowed", index, item.Type)
	}
}

func newDataplaneARPMatch(item *types.ARPMatch, index int) (*rule.ARPMatch, error) {
	if item == nil {
		return nil, nil
	}
	operation := strings.ToLower(strings.TrimSpace(item.Operation))
	switch operation {
	case "request", "reply":
		return &rule.ARPMatch{Operation: operation}, nil
	default:
		return nil, types.NewValidationError("rules[%d].match.arp.operation %q is not allowed", index, item.Operation)
	}
}

func normalizeDataplaneAction(item types.Rule, index int) (string, error) {
	action, ok := rule.NormalizeActionName(item.Response.Action)
	if ok {
		return action, nil
	}
	if strings.TrimSpace(item.Response.Action) == "" {
		return "", types.NewValidationError("rules[%d].response.action is required", index)
	}
	return "", types.NewValidationError("rules[%d].response.action %q is not allowed", index, item.Response.Action)
}

func validateDataplaneActionMatch(action string, match rule.RuleMatch, index int) error {
	switch action {
	case "none", "alert":
		return nil
	case "tcp_reset":
		if match.Protocol != "tcp" {
			return types.NewValidationError("rules[%d].response.action tcp_reset requires match.protocol tcp", index)
		}
	case "icmp_echo_reply":
		if match.Protocol != "icmp" {
			return types.NewValidationError("rules[%d].response.action icmp_echo_reply requires match.protocol icmp", index)
		}
		if match.ICMP == nil || match.ICMP.Type != "echo_request" {
			return types.NewValidationError("rules[%d].response.action icmp_echo_reply requires match.icmp.type echo_request", index)
		}
	case "tcp_syn_ack":
		if match.Protocol != "tcp" {
			return types.NewValidationError("rules[%d].response.action tcp_syn_ack requires match.protocol tcp", index)
		}
		if match.TCPFlags.SYN == nil || !*match.TCPFlags.SYN {
			return types.NewValidationError("rules[%d].response.action tcp_syn_ack requires match.tcp_flags.syn true", index)
		}
	case "icmp_port_unreachable", "icmp_host_unreachable", "icmp_admin_prohibited", "udp_echo_reply", "dns_refused", "dns_sinkhole":
		if match.Protocol != "udp" {
			return types.NewValidationError("rules[%d].response.action %s requires match.protocol udp", index, action)
		}
	case "arp_reply":
		if match.Protocol != "arp" {
			return types.NewValidationError("rules[%d].response.action arp_reply requires match.protocol arp", index)
		}
		if match.ARP == nil || match.ARP.Operation != "request" {
			return types.NewValidationError("rules[%d].response.action arp_reply requires match.arp.operation request", index)
		}
	}
	return nil
}

func cloneRuleSet(set rule.RuleSet) rule.RuleSet {
	return rule.RuleSet{Rules: cloneDataplaneRules(set.Rules)}
}

func cloneDataplaneRules(items []rule.Rule) []rule.Rule {
	if items == nil {
		return nil
	}
	out := make([]rule.Rule, len(items))
	for i, item := range items {
		out[i] = cloneDataplaneRule(item)
	}
	return out
}

func cloneDataplaneRule(item rule.Rule) rule.Rule {
	return rule.Rule{
		ID:       item.ID,
		Name:     item.Name,
		Enabled:  item.Enabled,
		Priority: item.Priority,
		Match: rule.RuleMatch{
			Protocol:    item.Match.Protocol,
			VLANs:       append([]int(nil), item.Match.VLANs...),
			SrcPrefixes: append([]string(nil), item.Match.SrcPrefixes...),
			DstPrefixes: append([]string(nil), item.Match.DstPrefixes...),
			SrcPorts:    append([]int(nil), item.Match.SrcPorts...),
			DstPorts:    append([]int(nil), item.Match.DstPorts...),
			TCPFlags: rule.TCPFlags{
				SYN: cloneBool(item.Match.TCPFlags.SYN),
				ACK: cloneBool(item.Match.TCPFlags.ACK),
				RST: cloneBool(item.Match.TCPFlags.RST),
				FIN: cloneBool(item.Match.TCPFlags.FIN),
				PSH: cloneBool(item.Match.TCPFlags.PSH),
			},
			ICMP: cloneDataplaneICMPMatch(item.Match.ICMP),
			ARP:  cloneDataplaneARPMatch(item.Match.ARP),
		},
		Response: rule.RuleResponse{
			Action: item.Response.Action,
			Params: cloneRuleParams(item.Response.Params),
		},
	}
}

func cloneDataplaneICMPMatch(item *rule.ICMPMatch) *rule.ICMPMatch {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}

func cloneDataplaneARPMatch(item *rule.ARPMatch) *rule.ARPMatch {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}

func cloneRuleParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for key, value := range params {
		out[key] = value
	}
	return out
}

func cloneRuleset(ruleset types.Ruleset) types.Ruleset {
	return types.Ruleset{
		Version: ruleset.Version,
		Rules:   cloneRules(ruleset.Rules),
	}
}

func cloneRules(rules []types.Rule) []types.Rule {
	if rules == nil {
		return nil
	}
	out := make([]types.Rule, len(rules))
	for i, item := range rules {
		out[i] = cloneRule(item)
	}
	return out
}

func cloneRule(item types.Rule) types.Rule {
	return types.Rule{
		RuleID:   item.RuleID,
		Priority: item.Priority,
		Match: types.RuleMatch{
			Protocol:    item.Match.Protocol,
			VLANs:       append([]int(nil), item.Match.VLANs...),
			SrcPrefixes: append([]string(nil), item.Match.SrcPrefixes...),
			DstPrefixes: append([]string(nil), item.Match.DstPrefixes...),
			SrcPorts:    append([]int(nil), item.Match.SrcPorts...),
			DstPorts:    append([]int(nil), item.Match.DstPorts...),
			TCPFlags: types.TCPFlags{
				SYN: cloneBool(item.Match.TCPFlags.SYN),
				ACK: cloneBool(item.Match.TCPFlags.ACK),
				RST: cloneBool(item.Match.TCPFlags.RST),
				FIN: cloneBool(item.Match.TCPFlags.FIN),
				PSH: cloneBool(item.Match.TCPFlags.PSH),
			},
			ICMP: cloneAgentICMPMatch(item.Match.ICMP),
			ARP:  cloneAgentARPMatch(item.Match.ARP),
		},
		Response: types.RuleResponse{
			Action: item.Response.Action,
			Params: cloneRuleParams(item.Response.Params),
		},
	}
}

func cloneAgentICMPMatch(item *types.ICMPMatch) *types.ICMPMatch {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}

func cloneAgentARPMatch(item *types.ARPMatch) *types.ARPMatch {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}

func cloneBool(item *bool) *bool {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}
