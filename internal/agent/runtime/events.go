package runtime

import (
	"context"
	"fmt"
	"sync"

	"sidersp/internal/agent/service"
	"sidersp/internal/agent/types"
	"sidersp/internal/model"
)

func (r *DataplaneAttachmentRuntime) SubscribeEvents(ctx context.Context) (<-chan types.Event, error) {
	entries := r.enabledDataplaneRuntimes()
	if len(entries) == 0 {
		return nil, nil
	}

	runCtx, cancel := context.WithCancel(ctx)
	out := make(chan types.Event, len(entries))
	var wg sync.WaitGroup

	for _, entry := range entries {
		events, err := entry.runtime.SubscribeEvents(runCtx)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("subscribe dataplane events for attachment %d: %w", entry.ifindex, err)
		}

		wg.Add(1)
		go func(events <-chan model.EventRecord) {
			defer wg.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				case item, ok := <-events:
					if !ok {
						return
					}
					next := service.NewEventFromDataplane(item)
					select {
					case out <- next:
					case <-runCtx.Done():
						return
					}
				}
			}
		}(events)
	}

	go func() {
		wg.Wait()
		cancel()
		close(out)
	}()

	return out, nil
}
