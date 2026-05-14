package api

type Handler struct {
	status   StatusService
	ruleset  RulesetService
	response ResponseService
	dispatch DispatchService
}

func NewHandler(status StatusService, ruleset RulesetService, response ResponseService, dispatch DispatchService) Handler {
	if status == nil {
		panic("agent api: status service is required")
	}
	if ruleset == nil {
		panic("agent api: ruleset service is required")
	}
	if response == nil {
		panic("agent api: response service is required")
	}
	if dispatch == nil {
		panic("agent api: dispatch service is required")
	}
	return Handler{
		status:   status,
		ruleset:  ruleset,
		response: response,
		dispatch: dispatch,
	}
}
