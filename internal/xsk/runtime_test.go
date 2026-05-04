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

func TestNewRuntimeAssignsWorkerCPUs(t *testing.T) {
	t.Parallel()

	cfg := afxdp.DefaultSocketConfig()
	cfg.IfIndex = 7

	runtime, err := NewRuntime(Options{
		IfIndex:    7,
		Queues:     []int{2, 4},
		WorkerCPUs: []int{5, 6},
		AFXDP:      cfg,
	}, RuntimeDeps{
		Registrar: &stubRegistrar{},
		Consumers: Consumers{Response: &stubResponseConsumer{}},
		NewSocket: func(queueID int) (Socket, error) {
			return &stubSocket{fd: uint32(100 + queueID)}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	defer runtime.Close()

	if len(runtime.group.workers) != 2 {
		t.Fatalf("worker count = %d, want 2", len(runtime.group.workers))
	}

	workerA, ok := runtime.group.workers[0].Worker.(*Worker)
	if !ok {
		t.Fatalf("worker[0] type = %T, want *Worker", runtime.group.workers[0].Worker)
	}
	workerB, ok := runtime.group.workers[1].Worker.(*Worker)
	if !ok {
		t.Fatalf("worker[1] type = %T, want *Worker", runtime.group.workers[1].Worker)
	}

	if !workerA.pinCPU || workerA.cpuID != 5 {
		t.Fatalf("worker[0] cpu affinity = enabled:%v cpu:%d, want true/5", workerA.pinCPU, workerA.cpuID)
	}
	if !workerB.pinCPU || workerB.cpuID != 6 {
		t.Fatalf("worker[1] cpu affinity = enabled:%v cpu:%d, want true/6", workerB.pinCPU, workerB.cpuID)
	}
}
