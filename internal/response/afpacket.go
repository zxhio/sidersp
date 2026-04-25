package response

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

type afpacketFrameSender struct {
	ifindex int
	fd      int
	mu      sync.Mutex
}

func newAFPacketFrameSender(ifaceName string) (*afpacketFrameSender, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup af_packet interface %s: %w", ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("create af_packet socket: %w", err)
	}

	return &afpacketFrameSender{
		ifindex: iface.Index,
		fd:      fd,
	}, nil
}

func (s *afpacketFrameSender) SendFrame(ctx context.Context, frame []byte) error {
	return s.send(ctx, frame)
}

func (s *afpacketFrameSender) SendBorrowedFrame(ctx context.Context, frame []byte) error {
	return s.send(ctx, frame)
}

func (s *afpacketFrameSender) send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := unix.Sendto(s.fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  s.ifindex,
		Protocol: htons(unix.ETH_P_ALL),
	}); err != nil {
		return fmt.Errorf("send af_packet frame on ifindex %d: %w", s.ifindex, err)
	}
	return nil
}

func (s *afpacketFrameSender) Close() error {
	if s == nil || s.fd == 0 {
		return nil
	}
	return unix.Close(s.fd)
}

func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return binary.LittleEndian.Uint16(buf[:])
}
