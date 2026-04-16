package console

import (
	"sidersp/internal/controlplane"
	"sidersp/internal/rule"
)

type Rule = rule.Rule

type RuleMatch = rule.RuleMatch

type RuleResponse = rule.RuleResponse

type CreateRuleRequest struct {
	ID       int          `json:"id"`
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	Priority int          `json:"priority"`
	Match    RuleMatch    `json:"match"`
	Response RuleResponse `json:"response"`
}

type UpdateRuleRequest struct {
	ID       int          `json:"id"`
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	Priority int          `json:"priority"`
	Match    RuleMatch    `json:"match"`
	Response RuleResponse `json:"response"`
}

type RuleResponseBody struct {
	ID       int          `json:"id"`
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	Priority int          `json:"priority"`
	Match    RuleMatch    `json:"match"`
	Response RuleResponse `json:"response"`
}

type StatusResponse struct {
	RulesPath  string `json:"rules_path"`
	ListenAddr string `json:"listen_addr"`
	Interface  string `json:"interface"`
	TotalRules int    `json:"total_rules"`
	Enabled    int    `json:"enabled_rules"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type dataEnvelope struct {
	Data any `json:"data"`
}

type listEnvelope struct {
	Data     any `json:"data"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

func newRuleResponse(item Rule) RuleResponseBody {
	return RuleResponseBody{
		ID:       item.ID,
		Name:     item.Name,
		Enabled:  item.Enabled,
		Priority: item.Priority,
		Match:    item.Match,
		Response: item.Response,
	}
}

func newRulesResponse(items []Rule) []RuleResponseBody {
	out := make([]RuleResponseBody, 0, len(items))
	for _, item := range items {
		out = append(out, newRuleResponse(item))
	}
	return out
}

func (r CreateRuleRequest) toRule() Rule {
	return Rule{
		ID:       r.ID,
		Name:     r.Name,
		Enabled:  r.Enabled,
		Priority: r.Priority,
		Match:    r.Match,
		Response: r.Response,
	}
}

func (r UpdateRuleRequest) toRule() Rule {
	return Rule{
		ID:       r.ID,
		Name:     r.Name,
		Enabled:  r.Enabled,
		Priority: r.Priority,
		Match:    r.Match,
		Response: r.Response,
	}
}

func newStatusResponse(item Status) StatusResponse {
	return StatusResponse{
		RulesPath:  item.RulesPath,
		ListenAddr: item.ListenAddr,
		Interface:  item.Interface,
		TotalRules: item.TotalRules,
		Enabled:    item.Enabled,
	}
}

type Status = controlplane.Status
