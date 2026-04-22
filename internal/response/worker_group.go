package response

import (
	"context"
	"fmt"
	"sync"
)

type WorkerRunner interface {
	Run(context.Context) error
}

type WorkerSpec struct {
	QueueID int
	Worker  WorkerRunner
}

type WorkerGroup struct {
	workers []WorkerSpec
}

func NewWorkerGroup(workers []WorkerSpec) (*WorkerGroup, error) {
	if len(workers) == 0 {
		return nil, fmt.Errorf("create worker group: at least one worker is required")
	}

	seen := make(map[int]struct{}, len(workers))
	items := make([]WorkerSpec, len(workers))
	for i, worker := range workers {
		if worker.QueueID < 0 {
			return nil, fmt.Errorf("create worker group: queue %d out of range", worker.QueueID)
		}
		if worker.Worker == nil {
			return nil, fmt.Errorf("create worker group: worker for queue %d is required", worker.QueueID)
		}
		if _, ok := seen[worker.QueueID]; ok {
			return nil, fmt.Errorf("create worker group: duplicate queue %d", worker.QueueID)
		}
		seen[worker.QueueID] = struct{}{}
		items[i] = worker
	}

	return &WorkerGroup{workers: items}, nil
}

func (g *WorkerGroup) Run(ctx context.Context) error {
	if g == nil {
		return fmt.Errorf("run worker group: nil group")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, len(g.workers))
	var wg sync.WaitGroup
	for _, spec := range g.workers {
		spec := spec
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- spec.Worker.Run(runCtx)
		}()
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	var firstErr error
	for err := range errCh {
		if err == nil {
			continue
		}
		if firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}
