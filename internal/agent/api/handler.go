package api

type Handler struct {
	status StatusService
}

func NewHandler(status StatusService) Handler {
	if status == nil {
		panic("agent api: status service is required")
	}
	return Handler{status: status}
}
