package analysis

import (
	"context"
	"errors"
	"testing"
	"time"

	"sidersp/internal/xsk"
)

type stubPacketSender struct {
	sendCalls  int
	closeCalls int
	frames     [][]byte
	sendErr    error
	sendHook   func([]byte)
}

func (s *stubPacketSender) WriteFrame(_ context.Context, frame []byte) error {
	s.sendCalls++
	s.frames = append(s.frames, append([]byte(nil), frame...))
	if s.sendHook != nil {
		s.sendHook(frame)
	}
	return s.sendErr
}

func (s *stubPacketSender) Close() error {
	s.closeCalls++
	return nil
}

func TestRuntimeSubmitRejectsFullQueue(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(Options{QueueSize: 1}, &stubPacketSender{})
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

	if err := runtime.SubmitXSK(context.Background(), xsk.Envelope{QueueID: 2}); err != nil {
		t.Fatalf("SubmitXSK() other queue error = %v, want nil", err)
	}
}

func TestRuntimeRunStopsOnCancel(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(Options{}, &stubPacketSender{})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestNewRuntimeUsesDefaultQueueSize(t *testing.T) {
	t.Parallel()

	runtime, err := NewRuntime(Options{}, &stubPacketSender{})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if err := runtime.SubmitXSK(context.Background(), xsk.Envelope{QueueID: 7}); err != nil {
		t.Fatalf("SubmitXSK() error = %v", err)
	}

	shard := runtime.queues[7]
	if shard == nil {
		t.Fatal("queue shard = nil, want shard for queue 7")
	}
	if cap(shard.queue) != defaultQueueSize {
		t.Fatalf("queue cap = %d, want %d", cap(shard.queue), defaultQueueSize)
	}
}

func TestRuntimeRunExportsFrames(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	lockCalls := 0
	unlockCalls := 0
	affinityCalls := 0
	affinityCPU := -1
	sender := &stubPacketSender{
		sendHook: func(_ []byte) {
			cancel()
		},
	}
	runtime, err := NewRuntime(Options{}, sender)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	runtime.lockOSThread = func() {
		lockCalls++
	}
	runtime.unlockOSThread = func() {
		unlockCalls++
	}
	runtime.cpuByQueue = map[int]int{1: 7}
	runtime.setAffinity = func(cpuID int) error {
		affinityCalls++
		affinityCPU = cpuID
		return nil
	}
	if err := runtime.SubmitXSK(ctx, xsk.Envelope{
		QueueID: 1,
		Frame:   []byte{1, 2, 3, 4},
	}); err != nil {
		t.Fatalf("SubmitXSK() error = %v", err)
	}

	if err := runtime.Run(ctx); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if sender.sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sender.sendCalls)
	}
	if len(sender.frames) != 1 || len(sender.frames[0]) != 4 {
		t.Fatalf("frames = %+v, want one exported frame", sender.frames)
	}
	if lockCalls != 1 || unlockCalls != 1 {
		t.Fatalf("thread locker calls = %d/%d, want 1/1", lockCalls, unlockCalls)
	}
	if affinityCalls != 1 || affinityCPU != 7 {
		t.Fatalf("affinity calls = %d cpu = %d, want 1/7", affinityCalls, affinityCPU)
	}
}

func TestRuntimeRunExportsFramesSubmittedAfterStart(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	sender := &stubPacketSender{
		sendHook: func(_ []byte) {
			cancel()
		},
	}
	runtime, err := NewRuntime(Options{}, sender)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- runtime.Run(ctx)
	}()

	deadline := time.Now().Add(time.Second)
	started := false
	for time.Now().Before(deadline) {
		runtime.mu.Lock()
		started = runtime.runCtx != nil
		runtime.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !started {
		t.Fatal("runtime did not enter running state before submit")
	}

	if err := runtime.SubmitXSK(context.Background(), xsk.Envelope{
		QueueID: 3,
		Frame:   []byte{9, 8, 7, 6},
	}); err != nil {
		t.Fatalf("SubmitXSK() error = %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if sender.sendCalls != 1 {
		t.Fatalf("send calls = %d, want 1", sender.sendCalls)
	}
	if len(sender.frames) != 1 || len(sender.frames[0]) != 4 {
		t.Fatalf("frames = %+v, want one exported frame", sender.frames)
	}
}

func TestRuntimeCloseClosesSender(t *testing.T) {
	t.Parallel()

	sender := &stubPacketSender{}
	runtime, err := NewRuntime(Options{}, sender)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if sender.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", sender.closeCalls)
	}
}
