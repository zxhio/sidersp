package xsk

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"sidersp/internal/frameio"
	"sidersp/internal/logs"
)

type Registrar interface {
	RegisterXSK(queueID int, fd uint32) error
}

type Socket = frameio.Socket

type FrameHandler func(ctx context.Context, queueID int, socket Socket, frame []byte) error

type threadLocker interface {
	LockOSThread()
	UnlockOSThread()
}

type runtimeThreadLocker struct{}

func (runtimeThreadLocker) LockOSThread()   { runtime.LockOSThread() }
func (runtimeThreadLocker) UnlockOSThread() { runtime.UnlockOSThread() }

type Worker struct {
	ifindex   int
	queueID   int
	registrar Registrar
	socket    Socket
	handler   FrameHandler
	thread    threadLocker
	pinCPU    bool
	cpuID     int
	affinity  func(int) error
}

func NewWorker(ifindex, queueID int, registrar Registrar, socket Socket, handler FrameHandler) (*Worker, error) {
	if registrar == nil {
		return nil, fmt.Errorf("create xsk worker: registrar is required")
	}
	if socket == nil {
		return nil, fmt.Errorf("create xsk worker: socket is required")
	}
	if handler == nil {
		return nil, fmt.Errorf("create xsk worker: frame handler is required")
	}
	if queueID < 0 {
		return nil, fmt.Errorf("create xsk worker: queue %d out of range", queueID)
	}
	return &Worker{
		ifindex:   ifindex,
		queueID:   queueID,
		registrar: registrar,
		socket:    socket,
		handler:   handler,
		thread:    runtimeThreadLocker{},
		affinity:  setCurrentThreadAffinity,
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	locker := w.thread
	if locker == nil {
		locker = runtimeThreadLocker{}
	}
	locker.LockOSThread()
	defer locker.UnlockOSThread()

	if w.pinCPU {
		setAffinity := w.affinity
		if setAffinity == nil {
			setAffinity = setCurrentThreadAffinity
		}
		if err := setAffinity(w.cpuID); err != nil {
			return fmt.Errorf("pin xsk worker queue %d to cpu %d: %w", w.queueID, w.cpuID, err)
		}
	}

	if err := w.registrar.RegisterXSK(w.queueID, w.socket.FD()); err != nil {
		return err
	}

	logs.App().WithFields(logrus.Fields{
		"ifindex": w.ifindex,
		"queue":   w.queueID,
	}).Info("Started xsk worker")

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		frame, err := w.socket.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if len(frame) == 0 {
			continue
		}
		if err := w.handler(ctx, w.queueID, w.socket, frame); err != nil {
			logs.App().WithFields(logrus.Fields{
				"ifindex": w.ifindex,
				"queue":   w.queueID,
			}).WithError(err).Debug("XSK frame handler error")
		}
	}
}

func setCurrentThreadAffinity(cpuID int) error {
	var cpus unix.CPUSet
	cpus.Zero()
	cpus.Set(cpuID)
	return unix.SchedSetaffinity(0, &cpus)
}
