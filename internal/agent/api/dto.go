package api

import "sidersp/internal/agent/types"

type HealthResponse struct {
	Status string `json:"status"`
}

type StatusResponse struct {
	Status             string `json:"status"`
	Attachments        int    `json:"attachments"`
	RulesetVersion     uint64 `json:"ruleset_version"`
	ResponseConfigured bool   `json:"response_configured"`
	DispatchEnabled    bool   `json:"dispatch_enabled"`
}

func newHealthResponse(item types.Health) HealthResponse {
	return HealthResponse{Status: item.Status}
}

func newStatusResponse(item types.Status) StatusResponse {
	return StatusResponse{
		Status:             item.Status,
		Attachments:        item.Attachments,
		RulesetVersion:     item.RulesetVersion,
		ResponseConfigured: item.ResponseConfigured,
		DispatchEnabled:    item.DispatchEnabled,
	}
}
