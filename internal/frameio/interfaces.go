package frameio

import (
	"context"
	"io"
)

type WriteCloser interface {
	WriteFrame(context.Context, []byte) error
	io.Closer
}

type Socket interface {
	FD() uint32
	ReadFrame(context.Context) ([]byte, error)
	WriteCloser
}

type BorrowedFrameReader interface {
	ReadBorrowedFrame(context.Context) ([]byte, error)
	ReleaseBorrowedFrame()
}

type BorrowedFrameWriter interface {
	WriteBorrowedFrame(context.Context, []byte) error
}

type BorrowedIPv4PacketWriter interface {
	WriteBorrowedIPv4Packet(context.Context, []byte) error
}
