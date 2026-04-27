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
	frameFD int
	ipv4FD  int
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

	ipv4FD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("create raw ipv4 socket: %w", err)
	}
	if err := unix.SetsockoptString(ipv4FD, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName); err != nil {
		unix.Close(ipv4FD)
		unix.Close(fd)
		return nil, fmt.Errorf("bind raw ipv4 socket to %s: %w", ifaceName, err)
	}
	if err := unix.SetsockoptInt(ipv4FD, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(ipv4FD)
		unix.Close(fd)
		return nil, fmt.Errorf("enable raw ipv4 hdrincl on %s: %w", ifaceName, err)
	}

	return &afpacketFrameSender{
		ifindex: iface.Index,
		frameFD: fd,
		ipv4FD:  ipv4FD,
	}, nil
}

func (s *afpacketFrameSender) SendFrame(ctx context.Context, frame []byte) error {
	return s.send(ctx, frame)
}

func (s *afpacketFrameSender) SendBorrowedFrame(ctx context.Context, frame []byte) error {
	return s.send(ctx, frame)
}

func (s *afpacketFrameSender) SendBorrowedIPv4Packet(ctx context.Context, packet []byte) error {
	return s.sendIPv4Packet(ctx, packet)
}

func (s *afpacketFrameSender) send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := unix.Sendto(s.frameFD, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  s.ifindex,
		Protocol: htons(unix.ETH_P_ALL),
	}); err != nil {
		return fmt.Errorf("send af_packet frame on ifindex %d: %w", s.ifindex, err)
	}
	return nil
}

func (s *afpacketFrameSender) sendIPv4Packet(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	ip4, err := parseIPv4Packet(packet, "send raw ipv4 packet")
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := unix.Sendto(s.ipv4FD, packet, 0, &unix.SockaddrInet4{Addr: ip4.dst}); err != nil {
		return fmt.Errorf("send raw ipv4 packet on ifindex %d: %w", s.ifindex, err)
	}
	return nil
}

func (s *afpacketFrameSender) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.frameFD > 0 {
		if err := unix.Close(s.frameFD); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.ipv4FD > 0 {
		if err := unix.Close(s.ipv4FD); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return binary.LittleEndian.Uint16(buf[:])
}
