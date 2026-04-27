package dataplane

import (
	"fmt"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"sidersp/internal/logs"
)

const ifreqDataPad = 24 - unsafe.Sizeof(uintptr(0))

type ifreqEthtool struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [ifreqDataPad]byte
}

type ethtoolChannels struct {
	Cmd           uint32
	MaxRX         uint32
	MaxTX         uint32
	MaxOther      uint32
	MaxCombined   uint32
	RXCount       uint32
	TXCount       uint32
	OtherCount    uint32
	CombinedCount uint32
}

func configureInterfaceCombinedChannels(name string, combined int) error {
	if combined <= 0 {
		return nil
	}

	current, err := readInterfaceChannels(name)
	if err != nil {
		return fmt.Errorf("read combined channels on %s: %w", name, err)
	}
	if current.CombinedCount == uint32(combined) {
		logs.App().WithFields(logrus.Fields{
			"interface":         name,
			"combined_channels": combined,
		}).Info("Interface combined channels already configured")
		return nil
	}
	if current.MaxCombined == 0 {
		return fmt.Errorf("configure combined channels on %s: interface does not support combined channels", name)
	}
	if uint32(combined) > current.MaxCombined {
		return fmt.Errorf("configure combined channels on %s: requested %d exceeds max %d", name, combined, current.MaxCombined)
	}

	current.Cmd = unix.ETHTOOL_SCHANNELS
	current.CombinedCount = uint32(combined)
	if err := ioctlEthtoolChannels(name, &current); err != nil {
		return fmt.Errorf("set combined channels on %s to %d: %w", name, combined, err)
	}

	logs.App().WithFields(logrus.Fields{
		"interface":         name,
		"combined_channels": combined,
	}).Info("Configured interface combined channels")
	return nil
}

func readInterfaceChannels(name string) (ethtoolChannels, error) {
	channels := ethtoolChannels{Cmd: unix.ETHTOOL_GCHANNELS}
	if err := ioctlEthtoolChannels(name, &channels); err != nil {
		return ethtoolChannels{}, err
	}
	return channels, nil
}

func ioctlEthtoolChannels(name string, channels *ethtoolChannels) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	if len(name) >= unix.IFNAMSIZ {
		return unix.EINVAL
	}

	var req ifreqEthtool
	copy(req.name[:], name)
	req.data = unsafe.Pointer(channels)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCETHTOOL), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		return errno
	}
	return nil
}
