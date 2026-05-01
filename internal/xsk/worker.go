package xsk

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
)

type Registrar interface {
	RegisterXSK(queueID int, fd uint32) error
}

type Socket interface {
	FD() uint32
	Receive(context.Context) ([]byte, error)
	SendFrame(context.Context, []byte) error
	io.Closer
}

type FrameHandler func(ctx context.Context, queueID int, socket Socket, frame []byte) error

type Worker struct {
	ifindex   int
	queueID   int
	registrar Registrar
	socket    Socket
	handler   FrameHandler
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
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	if w == nil {
		return fmt.Errorf("run xsk worker: nil worker")
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

		frame, err := w.socket.Receive(ctx)
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
