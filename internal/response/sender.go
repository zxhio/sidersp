package response

import (
	"context"
	"sync"
)

type responseSender interface {
	Send(context.Context, XSKMetadata, []byte) error
	Backend() TXBackend
}

// borrowedFrameSender declares that SendBorrowedFrame consumes the frame
// synchronously and will not retain the slice after return.
type borrowedFrameSender interface {
	SendBorrowedFrame(context.Context, []byte) error
}

type afxdpSender struct {
	out       frameSender
	buildOpts BuildOptions
}

type afpacketSender struct {
	out       frameSender
	buildOpts BuildOptions
}

type pooledFrameBuffer struct {
	buf []byte
}

var responseFramePool = sync.Pool{
	New: func() any {
		return &pooledFrameBuffer{buf: make([]byte, 0, 2048)}
	},
}

func acquireResponseFrameBuffer() *pooledFrameBuffer {
	return responseFramePool.Get().(*pooledFrameBuffer)
}

func releaseResponseFrameBuffer(item *pooledFrameBuffer) {
	if item == nil {
		return
	}
	if cap(item.buf) > 8192 {
		item.buf = make([]byte, 0, 2048)
	} else {
		item.buf = item.buf[:0]
	}
	responseFramePool.Put(item)
}

func (s *afxdpSender) Send(ctx context.Context, meta XSKMetadata, frame []byte) error {
	return sendResponseFrame(ctx, s.out, meta, frame, s.buildOpts)
}

func (s *afxdpSender) Backend() TXBackend {
	return TXBackendAFXDP
}

func (s *afpacketSender) Send(ctx context.Context, meta XSKMetadata, frame []byte) error {
	return sendResponseFrame(ctx, s.out, meta, frame, s.buildOpts)
}

func (s *afpacketSender) Backend() TXBackend {
	return TXBackendAFPacket
}

func sendResponseFrame(ctx context.Context, out frameSender, meta XSKMetadata, frame []byte, buildOpts BuildOptions) error {
	if borrowed, ok := out.(borrowedFrameSender); ok {
		buf := acquireResponseFrameBuffer()
		defer releaseResponseFrameBuffer(buf)

		responseFrame, err := BuildResponseFrameToBuffer(meta, frame, buildOpts, buf.buf)
		if err != nil {
			return err
		}
		buf.buf = responseFrame
		return borrowed.SendBorrowedFrame(ctx, responseFrame)
	}

	responseFrame, err := BuildResponseFrame(meta, frame, buildOpts)
	if err != nil {
		return err
	}
	return out.SendFrame(ctx, responseFrame)
}
