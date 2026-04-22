package xsk

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// xskQueue is the shared ring buffer structure mapped from kernel memory.
type xskQueue[T any] struct {
	mem        []byte
	cachedProd uint32
	cachedCons uint32
	mask       uint32
	size       uint32
	producer   *uint32
	consumer   *uint32
	flags      *uint32
	ring       []T
}

func (q *xskQueue[T]) get(idx uint32) *T {
	return &q.ring[idx&q.mask]
}

// prodQueue is a producer-side ring (Fill, TX).
type prodQueue[T any] xskQueue[T]

func (q *prodQueue[T]) raw() *xskQueue[T] { return (*xskQueue[T])(q) }

// GetFreeNum returns the number of free slots, capped at n.
func (q *prodQueue[T]) GetFreeNum(n uint32) uint32 {
	entries := q.cachedCons - q.cachedProd
	if entries >= n {
		return entries
	}
	q.cachedCons = atomic.LoadUint32(q.consumer)
	q.cachedCons += q.size
	return q.cachedCons - q.cachedProd
}

// Reserve attempts to reserve n slots. Returns the number reserved and sets idx
// to the starting producer index.
func (q *prodQueue[T]) Reserve(n uint32, idx *uint32) uint32 {
	if q.GetFreeNum(n) < n {
		return 0
	}
	*idx = q.cachedProd
	q.cachedProd += n
	return n
}

// Submit advances the producer pointer by n, making reserved slots visible to
// the kernel.
func (q *prodQueue[T]) Submit(n uint32) {
	atomic.StoreUint32(q.producer, *q.producer+n)
}

// NeedWakeup returns true if the kernel needs an explicit wakeup via sendto.
func (q *prodQueue[T]) NeedWakeup() bool {
	return *q.flags&unix.XDP_RING_NEED_WAKEUP != 0
}

// consQueue is a consumer-side ring (RX, Completion).
type consQueue[T any] xskQueue[T]

func (q *consQueue[T]) raw() *xskQueue[T] { return (*xskQueue[T])(q) }

// GetAvailNum returns the number of available entries, capped at n.
func (q *consQueue[T]) GetAvailNum(n uint32) uint32 {
	entries := q.cachedProd - q.cachedCons
	if entries == 0 {
		q.cachedProd = atomic.LoadUint32(q.producer)
		entries = q.cachedProd - q.cachedCons
	}
	return min(entries, n)
}

// Peek returns up to n available entries and advances the cached consumer.
func (q *consQueue[T]) Peek(n uint32, idx *uint32) uint32 {
	entries := q.GetAvailNum(n)
	if entries > 0 {
		*idx = q.cachedCons
		q.cachedCons += entries
	}
	return entries
}

// Release advances the consumer pointer by n, telling the kernel these slots
// have been consumed.
func (q *consQueue[T]) Release(n uint32) {
	atomic.StoreUint32(q.consumer, *q.consumer+n)
}

// Ring types using embedding to promote base methods.
type (
	fillQueue       struct{ prodQueue[uint64] }
	completionQueue struct{ consQueue[uint64] }
	rxQueue         struct{ consQueue[unix.XDPDesc] }
	txQueue         struct{ prodQueue[unix.XDPDesc] }
)

func (q *fillQueue) GetAddr(idx uint32) *uint64       { return q.raw().get(idx) }
func (q *completionQueue) GetAddr(idx uint32) *uint64 { return q.raw().get(idx) }
func (q *rxQueue) GetDesc(idx uint32) *unix.XDPDesc   { return q.raw().get(idx) }
func (q *txQueue) GetDesc(idx uint32) *unix.XDPDesc   { return q.raw().get(idx) }

var (
	sizeofUint64  = uint64(unsafe.Sizeof(uint64(0)))
	sizeofXDPDesc = uint64(unsafe.Sizeof(unix.XDPDesc{}))
)

// initQueueByOffset initializes a ring queue from mmap'd memory using the
// kernel-provided offset structure.
func initQueueByOffset[T any](q *xskQueue[T], data []byte, off *unix.XDPRingOffset, size uint32) {
	q.mem = data
	q.producer = (*uint32)(unsafe.Pointer(&data[off.Producer]))
	q.consumer = (*uint32)(unsafe.Pointer(&data[off.Consumer]))
	q.flags = (*uint32)(unsafe.Pointer(&data[off.Flags]))
	q.ring = unsafe.Slice((*T)(unsafe.Pointer(&data[off.Desc])), size)
}
