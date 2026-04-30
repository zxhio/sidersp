package response

import (
	"context"
	"errors"
	"sync"
)

type responseSender interface {
	Send(context.Context, XSKMetadata, Builder, []byte, *Packet) error
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

var frameBufferPool = sync.Pool{
	New: func() any {
		return &pooledFrameBuffer{buf: make([]byte, 0, 2048)}
	},
}

func acquireFrameBuffer() *pooledFrameBuffer {
	return frameBufferPool.Get().(*pooledFrameBuffer)
}

func releaseFrameBuffer(item *pooledFrameBuffer) {
	if item == nil {
		return
	}
	if cap(item.buf) > 8192 {
		item.buf = make([]byte, 0, 2048)
	} else {
		item.buf = item.buf[:0]
	}
	frameBufferPool.Put(item)
}

func (s *afxdpSender) Send(ctx context.Context, meta XSKMetadata, builder Builder, frame []byte, pkt *Packet) error {
	return sendResponseFrame(ctx, s.out, meta, builder, frame, s.buildOpts, pkt)
}

func (s *afxdpSender) Backend() TXBackend {
	return TXBackendAFXDP
}

func (s *afpacketSender) Backend() TXBackend {
	return TXBackendAFPacket
}

func (s *afpacketSender) Send(ctx context.Context, meta XSKMetadata, builder Builder, frame []byte, pkt *Packet) error {
	return sendResponseFrame(ctx, s.out, meta, builder, frame, s.buildOpts, pkt)
}

func sendResponseFrame(ctx context.Context, out frameSender, meta XSKMetadata, builder Builder, frame []byte, buildOpts BuildOptions, pkt *Packet) error {
	if pkt == nil || builder == nil {
		engine := getResponseEngine()
		defer putResponseEngine(engine)

		context := buildContext(meta.Action)
		var err error
		pkt, builder, err = engine.ResolveBuilder(meta, frame, context)
		if err != nil {
			return err
		}
	}

	if borrowedIPv4, ok := out.(borrowedIPv4PacketSender); ok {
		buf := acquireFrameBuffer()
		defer releaseFrameBuffer(buf)

		responsePacket, err := buildResponseIPv4Packet(builder, meta, pkt, buildOpts, buf.buf)
		if err == nil {
			buf.buf = responsePacket
			return borrowedIPv4.SendBorrowedIPv4Packet(ctx, responsePacket)
		}
		if !errors.Is(err, errResponseRequiresEthernetFraming) {
			return err
		}
	}

	if borrowed, ok := out.(borrowedFrameSender); ok {
		buf := acquireFrameBuffer()
		defer releaseFrameBuffer(buf)

		responseFrame, err := buildResponseFrame(builder, meta, pkt, buildOpts, buf.buf)
		if err != nil {
			return err
		}
		buf.buf = responseFrame
		return borrowed.SendBorrowedFrame(ctx, responseFrame)
	}

	responseFrame, err := buildResponseFrame(builder, meta, pkt, buildOpts, nil)
	if err != nil {
		return err
	}
	return out.SendFrame(ctx, responseFrame)
}
