package xsk

import (
	"strings"
	"testing"

	"sidersp/internal/frameio/afxdp"
)

func TestNewRuntimeRejectsWorkerCPUCountMismatch(t *testing.T) {
	t.Parallel()

	cfg := afxdp.DefaultSocketConfig()
	cfg.IfIndex = 7

	_, err := NewRuntime(Options{
		IfIndex:    7,
		Queues:     []int{0, 1},
		WorkerCPUs: []int{3},
		AFXDP:      cfg,
	}, RuntimeDeps{})
	if err == nil {
		t.Fatal("NewRuntime() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "worker cpu count 1 must match queue count 2") {
		t.Fatalf("NewRuntime() error = %q, want worker cpu count mismatch", err)
	}
}
