package xsk

import (
	"strings"
	"testing"

	"sidersp/internal/frameio/afxdp"
)

func TestValidateOptionsRejectsWorkerCPUCountMismatch(t *testing.T) {
	t.Parallel()

	cfg := afxdp.DefaultSocketConfig()
	cfg.IfIndex = 7

	err := validateOptions(Options{
		IfIndex:    7,
		Queues:     []int{0, 1},
		WorkerCPUs: []int{3},
		AFXDP:      cfg,
	})
	if err == nil {
		t.Fatal("validateOptions() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "worker cpu count 1 must match queue count 2") {
		t.Fatalf("validateOptions() error = %q, want worker cpu count mismatch", err)
	}
}
