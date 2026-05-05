package dataplane

import (
	"sync"

	"sidersp/internal/model"
)

const defaultEventBufferSize = 2048

type eventBuffer struct {
	mu       sync.Mutex
	items    []model.EventRecord
	next     int
	capacity int
}

func newEventBuffer(capacity int) *eventBuffer {
	if capacity <= 0 {
		capacity = defaultEventBufferSize
	}
	return &eventBuffer{
		items:    make([]model.EventRecord, 0, capacity),
		capacity: capacity,
	}
}

func (b *eventBuffer) add(item model.EventRecord) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.items) < b.capacity {
		b.items = append(b.items, item)
		return
	}

	b.items[b.next] = item
	b.next = (b.next + 1) % b.capacity
}

func (b *eventBuffer) list() []model.EventRecord {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]model.EventRecord, 0, len(b.items))
	if len(b.items) < b.capacity {
		return append(out, b.items...)
	}

	out = append(out, b.items[b.next:]...)
	out = append(out, b.items[:b.next]...)
	return out
}
