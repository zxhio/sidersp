package response

import (
	"context"
	"errors"
	"sync"
)

type responseSender interface {
	Send(context.Context, XSKMetadata, []byte, *parsedFrame) error
	Backend() TXBackend
}

// borrowedFrameSender declares that SendBorrowedFrame consumes the frame
// synchronously and will not retain the slice after return.
type borrowedFrameSender interface {
	SendBorrowedFrame(context.Context, []byte) error
}

type borrowedIPv4PacketSender interface {
	SendBorrowedIPv4Packet(context.Context, []byte) error
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

func (s *afxdpSender) Send(ctx context.Context, meta XSKMetadata, frame []byte, pf *parsedFrame) error {
	return sendResponseFrame(ctx, s.out, meta, frame, s.buildOpts, pf)
}

func (s *afxdpSender) Backend() TXBackend {
	return TXBackendAFXDP
}

func (s *afpacketSender) Send(ctx context.Context, meta XSKMetadata, frame []byte, pf *parsedFrame) error {
	return sendResponseFrame(ctx, s.out, meta, frame, s.buildOpts, pf)
}

func (s *afpacketSender) Backend() TXBackend {
	return TXBackendAFPacket
}

func sendResponseFrame(ctx context.Context, out frameSender, meta XSKMetadata, frame []byte, buildOpts BuildOptions, pf *parsedFrame) error {
	if borrowedIPv4, ok := out.(borrowedIPv4PacketSender); ok {
		buf := acquireResponseFrameBuffer()
		defer releaseResponseFrameBuffer(buf)

		var responsePacket []byte
		var err error
		if pf != nil {
			responsePacket, err = BuildResponseIPv4PacketFromParsed(meta, pf, buildOpts, buf.buf)
		} else {
			responsePacket, err = BuildResponseIPv4PacketToBuffer(meta, frame, buildOpts, buf.buf)
		}
		if err == nil {
			buf.buf = responsePacket
			return borrowedIPv4.SendBorrowedIPv4Packet(ctx, responsePacket)
		}
		if !errors.Is(err, errResponseRequiresEthernetFraming) {
			return err
		}
	}

	if borrowed, ok := out.(borrowedFrameSender); ok {
		buf := acquireResponseFrameBuffer()
		defer releaseResponseFrameBuffer(buf)

		var responseFrame []byte
		var err error
		if pf != nil {
			responseFrame, err = BuildResponseFrameFromParsed(meta, pf, buildOpts, buf.buf)
		} else {
			responseFrame, err = BuildResponseFrameToBuffer(meta, frame, buildOpts, buf.buf)
		}
		if err != nil {
			return err
		}
		buf.buf = responseFrame
		return borrowed.SendBorrowedFrame(ctx, responseFrame)
	}

	var responseFrame []byte
	var err error
	if pf != nil {
		responseFrame, err = BuildResponseFrameFromParsed(meta, pf, buildOpts, nil)
	} else {
		responseFrame, err = BuildResponseFrame(meta, frame, buildOpts)
	}
	if err != nil {
		return err
	}
	return out.SendFrame(ctx, responseFrame)
}
