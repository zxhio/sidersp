package afpacket

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

const readPollTimeoutMS = 100

type Socket struct {
	ifindex int
	frameFD int
	ipv4FD  int
	mu      sync.Mutex
}

func New(ifaceName string) (*Socket, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup af_packet interface %s: %w", ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("create af_packet socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: htons(unix.ETH_P_ALL),
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind af_packet socket to %s: %w", ifaceName, err)
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

	return &Socket{
		ifindex: iface.Index,
		frameFD: fd,
		ipv4FD:  ipv4FD,
	}, nil
}

func (s *Socket) FD() uint32 {
	return uint32(s.frameFD)
}

func (s *Socket) ReadFrame(ctx context.Context) ([]byte, error) {
	pollFds := []unix.PollFd{
		{Fd: int32(s.frameFD), Events: unix.POLLIN},
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, nil
		}

		_, err := unix.Poll(pollFds, readPollTimeoutMS)
		if err != nil && err != unix.EINTR {
			return nil, fmt.Errorf("poll af_packet socket: %w", err)
		}
		if pollFds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		s.mu.Lock()
		buf := make([]byte, 65536)
		n, _, err := unix.Recvfrom(s.frameFD, buf, 0)
		s.mu.Unlock()
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("read af_packet frame on ifindex %d: %w", s.ifindex, err)
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

func (s *Socket) WriteFrame(ctx context.Context, frame []byte) error {
	return s.send(ctx, frame)
}

func (s *Socket) WriteBorrowedFrame(ctx context.Context, frame []byte) error {
	return s.send(ctx, frame)
}

func (s *Socket) WriteBorrowedIPv4Packet(ctx context.Context, packet []byte) error {
	return s.sendIPv4Packet(ctx, packet)
}

func (s *Socket) send(ctx context.Context, frame []byte) error {
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

func (s *Socket) sendIPv4Packet(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var ip4 layers.IPv4
	if err := ip4.DecodeFromBytes(packet, gopacket.NilDecodeFeedback); err != nil {
		return fmt.Errorf("send raw ipv4 packet: %w", err)
	}
	if len(ip4.DstIP) < 4 {
		return fmt.Errorf("send raw ipv4 packet: invalid ipv4 destination")
	}

	var dst [4]byte
	copy(dst[:], ip4.DstIP[:4])

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := unix.Sendto(s.ipv4FD, packet, 0, &unix.SockaddrInet4{Addr: dst}); err != nil {
		return fmt.Errorf("send raw ipv4 packet on ifindex %d: %w", s.ifindex, err)
	}
	return nil
}

func (s *Socket) Close() error {
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
