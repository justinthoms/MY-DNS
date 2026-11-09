//go:build linux

package anycast

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// SysLink switches interfaces with SIOCSIFFLAGS: the same as
// "ip link set dev X up|down", without needing iproute2. It needs
// CAP_NET_ADMIN in the interface's network namespace.
type SysLink struct{}

func ifaceFlags(fd int, name string) (*unix.Ifreq, uint16, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return nil, 0, fmt.Errorf("read flags of %s: %w", name, err)
	}
	return ifr, ifr.Uint16(), nil
}

// IsUp reports whether the interface is administratively up.
func (SysLink) IsUp(name string) (bool, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	_, flags, err := ifaceFlags(fd, name)
	return flags&unix.IFF_UP != 0, err
}

// SetUp brings the interface up or down.
func (SysLink) SetUp(name string, up bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, flags, err := ifaceFlags(fd, name)
	if err != nil {
		return err
	}
	if up {
		flags |= unix.IFF_UP
	} else {
		flags &^= unix.IFF_UP
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set %s %s: %w", name, map[bool]string{true: "up", false: "down"}[up], err)
	}
	return nil
}
