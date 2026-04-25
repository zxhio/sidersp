package response

import (
	"context"
	"fmt"
	"sync"
)

// borrowedFrameTransmitter declares that TransmitBorrowed consumes the frame
// synchronously and will not retain the slice after return.
type borrowedFrameTransmitter interface {
	TransmitBorrowed(context.Context, []byte) error
}

// borrowedICMPPacketSender declares that TransmitIPv4Borrowed consumes the
// packet synchronously and will not retain the slice after return.
type borrowedICMPPacketSender interface {
	TransmitIPv4Borrowed(context.Context, []byte) error
}

type sameInterfaceTX struct {
	tx frameTransmitter
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

func (t *sameInterfaceTX) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, opts BuildOptions) error {
	if borrowed, ok := t.tx.(borrowedFrameTransmitter); ok {
		buf := acquireResponseFrameBuffer()
		defer releaseResponseFrameBuffer(buf)

		responseFrame, err := BuildResponseFrameToBuffer(meta, frame, opts, buf.buf)
		if err != nil {
			return err
		}
		buf.buf = responseFrame
		return borrowed.TransmitBorrowed(ctx, responseFrame)
	}

	responseFrame, err := BuildResponseFrame(meta, frame, opts)
	if err != nil {
		return err
	}
	return t.tx.Transmit(ctx, responseFrame)
}

type icmpPacketSender interface {
	TransmitIPv4(context.Context, []byte) error
}

type icmpEgressTX struct {
	tx icmpPacketSender
}

func (t *icmpEgressTX) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, _ BuildOptions) error {
	if meta.Action != ActionICMPEchoReply {
		return fmt.Errorf("icmp egress transmitter: unsupported action %d", meta.Action)
	}

	if borrowed, ok := t.tx.(borrowedICMPPacketSender); ok {
		buf := acquireResponseFrameBuffer()
		defer releaseResponseFrameBuffer(buf)

		packet, err := BuildICMPEchoReplyIPv4ToBuffer(frame, buf.buf)
		if err != nil {
			return err
		}
		buf.buf = packet
		return borrowed.TransmitIPv4Borrowed(ctx, packet)
	}

	packet, err := BuildICMPEchoReplyIPv4(frame)
	if err != nil {
		return err
	}
	return t.tx.TransmitIPv4(ctx, packet)
}

type arpEgressTX struct {
	tx frameTransmitter
}

func (t *arpEgressTX) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, opts BuildOptions) error {
	if meta.Action != ActionARPReply {
		return fmt.Errorf("arp egress transmitter: unsupported action %d", meta.Action)
	}

	if borrowed, ok := t.tx.(borrowedFrameTransmitter); ok {
		buf := acquireResponseFrameBuffer()
		defer releaseResponseFrameBuffer(buf)

		responseFrame, err := BuildResponseFrameToBuffer(meta, frame, opts, buf.buf)
		if err != nil {
			return err
		}
		buf.buf = responseFrame
		return borrowed.TransmitBorrowed(ctx, responseFrame)
	}

	responseFrame, err := BuildResponseFrame(meta, frame, opts)
	if err != nil {
		return err
	}
	return t.tx.Transmit(ctx, responseFrame)
}

type actionTXMux struct {
	defaultTX actionTransmitter
	overrides map[uint16]actionTransmitter
}

func (t *actionTXMux) Transmit(ctx context.Context, meta XSKMetadata, frame []byte, opts BuildOptions) error {
	if override, ok := t.overrides[meta.Action]; ok {
		return override.Transmit(ctx, meta, frame, opts)
	}
	return t.defaultTX.Transmit(ctx, meta, frame, opts)
}
