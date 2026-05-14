package service

import (
	"context"

	"sidersp/internal/agent/types"
)

type RulesetService struct {
	runtime RulesetRuntime
}

func NewRulesetService(runtime RulesetRuntime) *RulesetService {
	if runtime == nil {
		panic("agent service: ruleset runtime is required")
	}
	return &RulesetService{runtime: runtime}
}

func (s *RulesetService) GetRuleset(ctx context.Context) (types.Ruleset, error) {
	return s.runtime.GetRuleset(ctx)
}

func (s *RulesetService) ReplaceRuleset(ctx context.Context, ruleset types.Ruleset, dryRun bool) (types.Ruleset, error) {
	if dryRun {
		if err := s.runtime.ValidateRuleset(ctx, ruleset); err != nil {
			return types.Ruleset{}, err
		}
		return cloneRuleset(ruleset), nil
	}
	return s.runtime.ReplaceRuleset(ctx, ruleset)
}

func (s *RulesetService) ClearRuleset(ctx context.Context) error {
	return s.runtime.ClearRuleset(ctx)
}

func validateRuleset(ruleset types.Ruleset) error {
	if ruleset.Version == 0 {
		return types.NewValidationError("version must be greater than 0")
	}
	if ruleset.Rules == nil {
		return types.NewValidationError("rules is required")
	}
	for i, item := range ruleset.Rules {
		if item.RuleID == 0 {
			return types.NewValidationError("rules[%d].rule_id is required", i)
		}
		if item.Priority < 0 {
			return types.NewValidationError("rules[%d].priority must be greater than or equal to 0", i)
		}
		if item.Response.Action == "" {
			return types.NewValidationError("rules[%d].response.action is required", i)
		}
	}
	return nil
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
		Match:    cloneRuleMatch(item.Match),
		Response: types.RuleResponse{
			Action: item.Response.Action,
			Params: cloneParams(item.Response.Params),
		},
	}
}

func cloneRuleMatch(item types.RuleMatch) types.RuleMatch {
	return types.RuleMatch{
		Protocol:    item.Protocol,
		VLANs:       append([]int(nil), item.VLANs...),
		SrcPrefixes: append([]string(nil), item.SrcPrefixes...),
		DstPrefixes: append([]string(nil), item.DstPrefixes...),
		SrcPorts:    append([]int(nil), item.SrcPorts...),
		DstPorts:    append([]int(nil), item.DstPorts...),
		TCPFlags:    cloneTCPFlags(item.TCPFlags),
		ICMP:        cloneICMPMatch(item.ICMP),
		ARP:         cloneARPMatch(item.ARP),
	}
}

func cloneTCPFlags(item types.TCPFlags) types.TCPFlags {
	return types.TCPFlags{
		SYN: cloneBool(item.SYN),
		ACK: cloneBool(item.ACK),
		RST: cloneBool(item.RST),
		FIN: cloneBool(item.FIN),
		PSH: cloneBool(item.PSH),
	}
}

func cloneICMPMatch(item *types.ICMPMatch) *types.ICMPMatch {
	if item == nil {
		return nil
	}
	next := *item
	return &next
}

func cloneARPMatch(item *types.ARPMatch) *types.ARPMatch {
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

func cloneParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}
	out := make(map[string]any, len(params))
	for key, value := range params {
		out[key] = value
	}
	return out
}
