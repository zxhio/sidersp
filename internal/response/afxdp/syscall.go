package afxdp

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// registerUmem registers a UMEM region with the AF_XDP socket via setsockopt.
func registerUmem(sockfd int, area []byte, cfg SocketConfig) error {
	reg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(unsafe.SliceData(area)))),
		Len:      uint64(len(area)),
		Size:     cfg.FrameSize,
		Headroom: 0,
		Flags:    0,
	}
	return setsockopt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg))
}

// getXDPMmapOffsets retrieves the mmap offset structure for the AF_XDP socket.
func getXDPMmapOffsets(fd int) (*unix.XDPMmapOffsets, error) {
	off := unix.XDPMmapOffsets{}
	optLen := uint32(unsafe.Sizeof(off))

	err := getsockopt(fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(&off), &optLen)
	if err != nil {
		return nil, fmt.Errorf("getsockopt(XDP_MMAP_OFFSETS): %w", err)
	}
	return &off, nil
}

func getsockopt(s int, level int, name int, val unsafe.Pointer, vallen *uint32) error {
	_, _, e1 := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(unsafe.Pointer(vallen)), 0)
	if e1 != 0 {
		return errnoErr(e1)
	}
	return nil
}

func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) error {
	_, _, e1 := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s), uintptr(level), uintptr(name), uintptr(val), uintptr(vallen), 0)
	if e1 != 0 {
		return errnoErr(e1)
	}
	return nil
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return unix.EAGAIN
	case unix.EINVAL:
		return unix.EINVAL
	case unix.ENOENT:
		return unix.ENOENT
	}
	return e
}
