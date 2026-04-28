package response

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
)

type XSKRegistrar interface {
	RegisterXSK(queueID int, fd uint32) error
}

// XSKHandler processes a single metadata-prefixed XSK frame.
type XSKHandler func(ctx context.Context, frame []byte) error

type XSKSocket interface {
	FD() uint32
	Receive(context.Context) ([]byte, error)
	frameSender
	io.Closer
}

type XSKWorker struct {
	ifindex   int
	queueID   int
	registrar XSKRegistrar
	socket    XSKSocket
	handler   XSKHandler
}

func NewXSKWorker(ifindex, queueID int, registrar XSKRegistrar, socket XSKSocket, handler XSKHandler) (*XSKWorker, error) {
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
	return &XSKWorker{
		ifindex:   ifindex,
		queueID:   queueID,
		registrar: registrar,
		socket:    socket,
		handler:   handler,
	}, nil
}

func (w *XSKWorker) Run(ctx context.Context) error {
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
		if err := w.handler(ctx, frame); err != nil {
			logs.App().WithFields(logrus.Fields{
				"ifindex": w.ifindex,
				"queue":   w.queueID,
			}).WithError(err).Debug("XSK frame handler error")
		}
	}
}
