package response

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type icmpEgressSender struct {
	ifaceName string
	conn      net.PacketConn
	rawConn   *ipv4.RawConn
	mu        sync.Mutex
}

func newICMPEgressSender(ifaceName string) (*icmpEgressSender, error) {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("listen raw icmp socket: %w", err)
	}
	if err := bindPacketConnToDevice(conn, ifaceName); err != nil {
		_ = conn.Close()
		return nil, err
	}

	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create raw ipv4 conn: %w", err)
	}

	return &icmpEgressSender{
		ifaceName: ifaceName,
		conn:      conn,
		rawConn:   rawConn,
	}, nil
}

func (t *icmpEgressSender) TransmitIPv4(ctx context.Context, packet []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	header, err := ipv4.ParseHeader(packet)
	if err != nil {
		return fmt.Errorf("parse ipv4 reply: %w", err)
	}
	if len(packet) < header.Len {
		return fmt.Errorf("parse ipv4 reply: truncated packet")
	}
	payload := append([]byte(nil), packet[header.Len:]...)

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.rawConn.WriteTo(header, payload, nil); err != nil {
		return fmt.Errorf("send icmp reply on %s: %w", t.ifaceName, err)
	}
	return nil
}

func (t *icmpEgressSender) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

type frameEgressSender struct {
	ifindex int
	fd      int
	mu      sync.Mutex
}

func newFrameEgressSender(ifaceName string) (*frameEgressSender, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("lookup frame egress interface %s: %w", ifaceName, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("create raw frame egress socket: %w", err)
	}

	return &frameEgressSender{
		ifindex: iface.Index,
		fd:      fd,
	}, nil
}

func (t *frameEgressSender) Transmit(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := unix.Sendto(t.fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  t.ifindex,
		Protocol: htons(unix.ETH_P_ALL),
	}); err != nil {
		return fmt.Errorf("send raw frame on ifindex %d: %w", t.ifindex, err)
	}
	return nil
}

func (t *frameEgressSender) Close() error {
	if t == nil || t.fd == 0 {
		return nil
	}
	return unix.Close(t.fd)
}

func bindPacketConnToDevice(conn net.PacketConn, ifaceName string) error {
	syscallConn, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return fmt.Errorf("bind raw icmp socket to %s: syscall conn is not supported", ifaceName)
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("bind raw icmp socket to %s: %w", ifaceName, err)
	}

	var bindErr error
	if err := rawConn.Control(func(fd uintptr) {
		bindErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifaceName)
	}); err != nil {
		return fmt.Errorf("bind raw icmp socket to %s: %w", ifaceName, err)
	}
	if bindErr != nil {
		return fmt.Errorf("bind raw icmp socket to %s: %w", ifaceName, bindErr)
	}
	return nil
}

func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return binary.LittleEndian.Uint16(buf[:])
}
