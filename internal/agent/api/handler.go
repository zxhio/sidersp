package api

type Handler struct {
	status  StatusService
	ruleset RulesetService
}

func NewHandler(status StatusService, ruleset RulesetService) Handler {
	if status == nil {
		panic("agent api: status service is required")
	}
	if ruleset == nil {
		panic("agent api: ruleset service is required")
	}
	return Handler{status: status, ruleset: ruleset}
}
