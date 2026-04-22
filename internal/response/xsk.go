package response

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/sirupsen/logrus"
)

const XSKMetadataSize = 8

// XSKMetadata mirrors BPF struct xsk_meta.
type XSKMetadata struct {
	RuleID   uint32
	Action   uint16
	Reserved uint16
}

type XSKRegistrar interface {
	RegisterXSKSocket(queueID int, fd uint32) error
}

type XSKFrameHandler interface {
	ExecuteXSKFrame(context.Context, []byte) error
}

type XSKSocket interface {
	FD() uint32
	Run(context.Context, XSKFrameHandler) error
}

type XSKWorker struct {
	ifindex   int
	queueID   int
	registrar XSKRegistrar
	socket    XSKSocket
	handler   XSKFrameHandler
}

func NewXSKWorker(ifindex, queueID int, registrar XSKRegistrar, socket XSKSocket, handler XSKFrameHandler) (*XSKWorker, error) {
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
	if err := w.registrar.RegisterXSKSocket(w.queueID, w.socket.FD()); err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"ifindex": w.ifindex,
		"queue":   w.queueID,
	}).Info("Started xsk worker")

	return w.socket.Run(ctx, w.handler)
}

func DecodeXSKMetadata(frame []byte) (XSKMetadata, []byte, error) {
	if len(frame) < XSKMetadataSize {
		return XSKMetadata{}, nil, fmt.Errorf("xsk frame too short: %d", len(frame))
	}

	meta := XSKMetadata{
		RuleID:   binary.LittleEndian.Uint32(frame[0:4]),
		Action:   binary.LittleEndian.Uint16(frame[4:6]),
		Reserved: binary.LittleEndian.Uint16(frame[6:8]),
	}
	return meta, frame[XSKMetadataSize:], nil
}
