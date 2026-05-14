package api

type Handler struct {
	status      StatusService
	ruleset     RulesetService
	attachments AttachmentService
	response    ResponseService
	dispatch    DispatchService
	stats       StatsService
	events      EventService
}

func NewHandler(status StatusService, ruleset RulesetService, attachments AttachmentService, response ResponseService, dispatch DispatchService, stats StatsService, events EventService) Handler {
	if status == nil {
		panic("agent api: status service is required")
	}
	if ruleset == nil {
		panic("agent api: ruleset service is required")
	}
	if attachments == nil {
		panic("agent api: attachment service is required")
	}
	if response == nil {
		panic("agent api: response service is required")
	}
	if dispatch == nil {
		panic("agent api: dispatch service is required")
	}
	if stats == nil {
		panic("agent api: stats service is required")
	}
	if events == nil {
		panic("agent api: event service is required")
	}
	return Handler{
		status:      status,
		ruleset:     ruleset,
		attachments: attachments,
		response:    response,
		dispatch:    dispatch,
		stats:       stats,
		events:      events,
	}
}
