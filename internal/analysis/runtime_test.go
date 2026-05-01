package analysis

import (
	"context"
	"errors"
	"testing"

	"sidersp/internal/xsk"
)

func TestRuntimeSubmitRejectsFullQueue(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(Options{QueueSize: 1})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	envelope := xsk.Envelope{QueueID: 1}
	if err := runtime.SubmitXSK(context.Background(), envelope); err != nil {
		t.Fatalf("SubmitXSK() error = %v", err)
	}
	err = runtime.SubmitXSK(context.Background(), envelope)
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("SubmitXSK() error = %v, want %v", err, ErrQueueFull)
	}
}

func TestRuntimeRunStopsOnCancel(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(Options{})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}
