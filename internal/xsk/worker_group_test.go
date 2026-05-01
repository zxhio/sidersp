package xsk

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type stubWorkerRunner struct {
	err     error
	wait    bool
	started chan struct{}
	calls   int
}

func (s *stubWorkerRunner) Run(ctx context.Context) error {
	s.calls++
	if s.started != nil {
		close(s.started)
	}
	if s.wait {
		<-ctx.Done()
		return ctx.Err()
	}
	return s.err
}

func TestNewWorkerGroupValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		workers []WorkerSpec
		want    string
	}{
		{
			name: "empty",
			want: "at least one worker is required",
		},
		{
			name: "negative queue",
			workers: []WorkerSpec{{
				QueueID: -1,
				Worker:  &stubWorkerRunner{},
			}},
			want: "queue -1 out of range",
		},
		{
			name: "nil worker",
			workers: []WorkerSpec{{
				QueueID: 0,
			}},
			want: "worker for queue 0 is required",
		},
		{
			name: "duplicate queue",
			workers: []WorkerSpec{
				{QueueID: 0, Worker: &stubWorkerRunner{}},
				{QueueID: 0, Worker: &stubWorkerRunner{}},
			},
			want: "duplicate queue 0",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewWorkerGroup(tc.workers)
			if err == nil {
				t.Fatal("NewWorkerGroup() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewWorkerGroup() error = %q, want %q", err, tc.want)
			}
		})
	}
}

func TestWorkerGroupRunCompletesWhenWorkersComplete(t *testing.T) {
	t.Parallel()

	workerA := &stubWorkerRunner{}
	workerB := &stubWorkerRunner{}
	group := newTestWorkerGroup(t, []WorkerSpec{
		{QueueID: 0, Worker: workerA},
		{QueueID: 1, Worker: workerB},
	})

	if err := group.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if workerA.calls != 1 || workerB.calls != 1 {
		t.Fatalf("worker calls = %d,%d; want 1,1", workerA.calls, workerB.calls)
	}
}

func TestWorkerGroupRunReturnsFirstErrorAndCancelsSiblings(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("worker failed")
	blockedStarted := make(chan struct{})
	failing := &stubWorkerRunner{err: wantErr}
	blocked := &stubWorkerRunner{wait: true, started: blockedStarted}
	group := newTestWorkerGroup(t, []WorkerSpec{
		{QueueID: 0, Worker: blocked},
		{QueueID: 1, Worker: failing},
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- group.Run(context.Background())
	}()
	<-blockedStarted

	select {
	case err := <-errCh:
		if !errors.Is(err, wantErr) {
			t.Fatalf("Run() error = %v, want %v", err, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Run() did not return after worker error")
	}
}

func TestWorkerGroupRunRespectsCanceledContext(t *testing.T) {
	t.Parallel()

	group := newTestWorkerGroup(t, []WorkerSpec{
		{QueueID: 0, Worker: &stubWorkerRunner{}},
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := group.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func newTestWorkerGroup(t *testing.T, workers []WorkerSpec) *WorkerGroup {
	t.Helper()

	group, err := NewWorkerGroup(workers)
	if err != nil {
		t.Fatalf("NewWorkerGroup() error = %v", err)
	}
	return group
}
