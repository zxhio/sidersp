package types

const (
	HealthStatusOK = "ok"

	StatusRunning  = "running"
	StatusDegraded = "degraded"
)

type Health struct {
	Status string
}

type Status struct {
	Status             string
	Attachments        int
	RulesetVersion     uint64
	ResponseConfigured bool
	DispatchEnabled    bool
}
