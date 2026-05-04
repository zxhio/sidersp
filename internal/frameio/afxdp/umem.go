package afxdp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

const invalidUMEMFrame = ^uint64(0)

// umem manages the shared user-space memory region for AF_XDP frames.
type umem struct {
	mem []byte

	frameAddrs   []uint64
	frameFreeNum uint32

	fill fillQueue
	comp completionQueue
}

// newUMEM creates a UMEM, registers it with the socket, mmaps the fill and
// completion rings, and pre-fills the fill ring with all available frames.
func newUMEM(sockfd int, cfg SocketConfig) (*umem, error) {
	area, err := unix.Mmap(-1, 0, int(cfg.FrameCount*cfg.FrameSize),
		unix.PROT_READ|unix.PROT_WRITE,
		int(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE))
	if err != nil {
		return nil, fmt.Errorf("mmap umem area: %w", err)
	}

	if err := registerUmem(sockfd, area, cfg); err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("register umem: %w", err)
	}

	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(cfg.FillRingSize)); err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("setsockopt XDP_UMEM_FILL_RING: %w", err)
	}
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(cfg.CompletionRingSize)); err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("setsockopt XDP_UMEM_COMPLETION_RING: %w", err)
	}

	off, err := getXDPMmapOffsets(sockfd)
	if err != nil {
		unix.Munmap(area)
		return nil, err
	}

	// mmap fill ring
	fillMem, err := unix.Mmap(sockfd, unix.XDP_UMEM_PGOFF_FILL_RING,
		int(off.Fr.Desc+uint64(cfg.FillRingSize)*sizeofUint64),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("mmap fill ring: %w", err)
	}

	var fill fillQueue
	initQueueByOffset(fill.raw(), fillMem, &off.Fr, cfg.FillRingSize)
	fill.mask = cfg.FillRingSize - 1
	fill.size = cfg.FillRingSize
	fill.cachedCons = cfg.FillRingSize

	// mmap completion ring
	compMem, err := unix.Mmap(sockfd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		int(off.Cr.Desc+uint64(cfg.CompletionRingSize)*sizeofUint64),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(area)
		unix.Munmap(fillMem)
		return nil, fmt.Errorf("mmap completion ring: %w", err)
	}

	var comp completionQueue
	initQueueByOffset(comp.raw(), compMem, &off.Cr, cfg.CompletionRingSize)
	comp.mask = cfg.CompletionRingSize - 1
	comp.size = cfg.CompletionRingSize

	// Build free frame stack
	frameAddrs := make([]uint64, cfg.FrameCount)
	for i := uint32(0); i < cfg.FrameCount; i++ {
		frameAddrs[i] = uint64(i * cfg.FrameSize)
	}

	umem := &umem{
		mem:          area,
		frameAddrs:   frameAddrs,
		frameFreeNum: cfg.FrameCount,
		fill:         fill,
		comp:         comp,
	}

	// Pre-fill the fill ring with all available frames
	var idx uint32
	umem.fill.Reserve(cfg.FillRingSize, &idx)
	for i := uint32(0); i < cfg.FillRingSize; i++ {
		*umem.fill.GetAddr(idx + i) = umem.allocFrame()
	}
	umem.fill.Submit(cfg.FillRingSize)

	return umem, nil
}

func (u *umem) allocFrame() uint64 {
	if u.frameFreeNum == 0 {
		return invalidUMEMFrame
	}
	u.frameFreeNum--
	addr := u.frameAddrs[u.frameFreeNum]
	u.frameAddrs[u.frameFreeNum] = invalidUMEMFrame
	return addr
}

func (u *umem) freeFrame(addr uint64) {
	u.frameAddrs[u.frameFreeNum] = addr
	u.frameFreeNum++
}

func (u *umem) frameData(addr uint64, len uint32) []byte {
	return u.mem[addr : addr+uint64(len)]
}

func (u *umem) frameFreeCount() uint32 {
	return u.frameFreeNum
}

func (u *umem) close() {
	unix.Munmap(u.mem)
	unix.Munmap(u.fill.raw().mem)
	unix.Munmap(u.comp.raw().mem)
}
