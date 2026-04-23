//go:build linux

package dataplane

import (
	"golang.org/x/sys/unix"
)

func interfacePromisc(name string) (bool, error) {
	flags, err := interfaceFlags(name)
	if err != nil {
		return false, err
	}
	return flags&uint16(unix.IFF_PROMISC) != 0, nil
}

func setInterfacePromisc(name string, enabled bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}

	flags := ifr.Uint16()
	if enabled {
		flags |= uint16(unix.IFF_PROMISC)
	} else {
		flags &^= uint16(unix.IFF_PROMISC)
	}
	ifr.SetUint16(flags)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

func interfaceFlags(name string) (uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return 0, err
	}
	return ifr.Uint16(), nil
}
