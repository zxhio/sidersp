package dataplane

import "strings"

const (
	ingressVerdictPass uint32 = iota
	ingressVerdictDrop
)

func ingressFailureVerdict(raw string) uint32 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "drop":
		return ingressVerdictDrop
	default:
		return ingressVerdictPass
	}
}
