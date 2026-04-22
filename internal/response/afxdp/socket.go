package afxdp

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Socket is an AF_XDP socket bound to a single queue.
type Socket struct {
	sockfd int
	umem   *umem
	rx     rxQueue
	tx     txQueue
	cfg    SocketConfig

	txStanding uint32
}

// NewSocket creates and binds an AF_XDP socket for the given queue ID.
func NewSocket(cfg SocketConfig, queueID int) (*Socket, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if queueID < 0 {
		return nil, fmt.Errorf("create af_xdp socket: queue %d out of range", queueID)
	}

	sockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("create af_xdp socket: %w", err)
	}

	umem, err := newUMEM(sockfd, cfg)
	if err != nil {
		unix.Close(sockfd)
		return nil, fmt.Errorf("create af_xdp umem: %w", err)
	}

	off, err := getXDPMmapOffsets(sockfd)
	if err != nil {
		umem.close()
		unix.Close(sockfd)
		return nil, err
	}

	// Create RX ring
	var rx rxQueue
	if cfg.RXRingSize != 0 {
		if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_RX_RING, int(cfg.RXRingSize)); err != nil {
			umem.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("setsockopt XDP_RX_RING: %w", err)
		}
		rxMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_RX_RING,
			int(off.Rx.Desc+uint64(cfg.RXRingSize)*sizeofXDPDesc),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			umem.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("mmap rx ring: %w", err)
		}
		initQueueByOffset(rx.raw(), rxMem, &off.Rx, cfg.RXRingSize)
		rx.mask = cfg.RXRingSize - 1
		rx.size = cfg.RXRingSize
		rx.cachedProd = atomic.LoadUint32(rx.producer)
		rx.cachedCons = atomic.LoadUint32(rx.consumer)
	}

	// Create TX ring
	var tx txQueue
	if cfg.TXRingSize != 0 {
		if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_TX_RING, int(cfg.TXRingSize)); err != nil {
			unix.Munmap(rx.raw().mem)
			umem.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("setsockopt XDP_TX_RING: %w", err)
		}
		txMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_TX_RING,
			int(off.Tx.Desc+uint64(cfg.TXRingSize)*sizeofXDPDesc),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			unix.Munmap(rx.raw().mem)
			umem.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("mmap tx ring: %w", err)
		}
		initQueueByOffset(tx.raw(), txMem, &off.Tx, cfg.TXRingSize)
		tx.mask = cfg.TXRingSize - 1
		tx.size = cfg.TXRingSize
		tx.cachedProd = atomic.LoadUint32(tx.producer)
		tx.cachedCons = atomic.LoadUint32(tx.consumer) + cfg.TXRingSize
	}

	// Bind socket to interface and queue
	addr := &unix.SockaddrXDP{
		Ifindex: uint32(cfg.IfIndex),
		QueueID: uint32(queueID),
		Flags:   cfg.BindFlags,
	}
	if err := unix.Bind(sockfd, addr); err != nil {
		unix.Munmap(rx.raw().mem)
		unix.Munmap(tx.raw().mem)
		umem.close()
		unix.Close(sockfd)
		return nil, fmt.Errorf("bind af_xdp socket queue %d: %w", queueID, err)
	}

	return &Socket{
		sockfd: sockfd,
		umem:   umem,
		rx:     rx,
		tx:     tx,
		cfg:    cfg,
	}, nil
}

// FD returns the AF_XDP socket file descriptor.
func (s *Socket) FD() uint32 {
	return uint32(s.sockfd)
}

// Receive polls the RX ring and returns one metadata-prefixed XSK frame. The
// returned slice is copied out of UMEM so callers do not hold AF_XDP frame
// ownership across response execution.
func (s *Socket) Receive(ctx context.Context) ([]byte, error) {
	pollFds := []unix.PollFd{
		{Fd: int32(s.sockfd), Events: unix.POLLIN},
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, nil
		}

		_, err := unix.Poll(pollFds, 100)
		if err != nil && err != unix.EINTR {
			return nil, fmt.Errorf("af_xdp poll: %w", err)
		}

		s.drainCompletions()
		frame := s.receiveFrame()
		if len(frame) != 0 {
			return frame, nil
		}
	}
}

// Transmit sends a response frame by allocating a UMEM slot, copying data,
// submitting a TX descriptor, and kicking the TX ring if needed.
func (s *Socket) Transmit(_ context.Context, frame []byte) error {
	if len(frame) > int(s.cfg.FrameSize) {
		return fmt.Errorf("transmit: frame length %d exceeds af_xdp frame size %d", len(frame), s.cfg.FrameSize)
	}

	addr := s.umem.allocFrame()
	if addr == invalidUMEMFrame {
		s.drainCompletions()
		addr = s.umem.allocFrame()
		if addr == invalidUMEMFrame {
			return fmt.Errorf("transmit: no free umem frames")
		}
	}

	data := s.umem.frameData(addr, uint32(len(frame)))
	copy(data, frame)

	var idx uint32
	if s.tx.Reserve(1, &idx) == 0 {
		s.umem.freeFrame(addr)
		return fmt.Errorf("transmit: tx ring full")
	}

	desc := s.tx.GetDesc(idx)
	desc.Addr = addr
	desc.Len = uint32(len(frame))
	s.tx.Submit(1)
	s.txStanding++

	if s.tx.NeedWakeup() {
		if err := unix.Sendto(s.sockfd, nil, unix.MSG_DONTWAIT, nil); err != nil {
			if !isExpectedErrno(err) {
				return fmt.Errorf("transmit sendto: %w", err)
			}
		}
	}

	return nil
}

// Close completes pending TX, unmaps all rings and UMEM, and closes the socket.
func (s *Socket) Close() error {
	s.completeAll()
	unix.Munmap(s.rx.raw().mem)
	unix.Munmap(s.tx.raw().mem)
	s.umem.close()
	return unix.Close(s.sockfd)
}

func (s *Socket) receiveFrame() []byte {
	var rxIdx uint32
	rcvd := s.rx.Peek(1, &rxIdx)
	if rcvd == 0 {
		return nil
	}

	desc := s.rx.GetDesc(rxIdx)
	frame := append([]byte(nil), s.umem.frameData(desc.Addr, desc.Len)...)
	s.umem.freeFrame(desc.Addr)

	s.rx.Release(rcvd)
	s.refillFill()
	return frame
}

func (s *Socket) refillFill() {
	toFill := s.umem.fill.GetFreeNum(s.umem.frameFreeCount())
	if toFill == 0 {
		return
	}

	var idx uint32
	if s.umem.fill.Reserve(toFill, &idx) < toFill {
		return
	}

	for i := uint32(0); i < toFill; i++ {
		*s.umem.fill.GetAddr(idx + i) = s.umem.allocFrame()
	}
	s.umem.fill.Submit(toFill)
}

func (s *Socket) drainCompletions() {
	if s.txStanding == 0 {
		return
	}

	if s.tx.NeedWakeup() {
		_ = unix.Sendto(s.sockfd, nil, unix.MSG_DONTWAIT, nil)
	}

	var idx uint32
	completed := s.umem.comp.Peek(s.txStanding, &idx)
	if completed == 0 {
		return
	}

	for i := uint32(0); i < completed; i++ {
		s.umem.freeFrame(*s.umem.comp.GetAddr(idx + i))
	}
	s.umem.comp.Release(completed)
	s.txStanding -= completed
}

func (s *Socket) completeAll() {
	retries := max(s.txStanding/64, 1)
	for s.txStanding != 0 && retries > 0 {
		s.drainCompletions()
		time.Sleep(10 * time.Millisecond)
		retries--
	}
}

func isExpectedErrno(err error) bool {
	if errno, ok := err.(unix.Errno); ok {
		return errno == unix.ENOBUFS || errno == unix.EAGAIN ||
			errno == unix.EBUSY || errno == unix.ENETDOWN
	}
	return false
}
