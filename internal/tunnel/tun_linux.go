//go:build linux

package tunnel

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"net/netip"
	"os"
)

type Device struct {
	f    *os.File
	Name string
	MTU  int
}

func Open(name string, mtu int) (*Device, error) {
	f, e := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	ifr, e := newIfreq(name)
	if e != nil {
		f.Close()
		return nil, e
	}
	if e = unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, ifr); e != nil {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", e)
	}
	return &Device{f: f, Name: ifr.Name(), MTU: mtu}, nil
}

func newIfreq(name string) (*unix.Ifreq, error) {
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	return ifr, nil
}

func (d *Device) Configure(prefix netip.Prefix) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return configureInterface(d.Name, prefix, d.MTU, func(req uint, ifr *unix.Ifreq) error {
		return unix.IoctlIfreq(fd, req, ifr)
	})
}

func configureInterface(name string, prefix netip.Prefix, mtu int, ioctl func(uint, *unix.Ifreq) error) error {
	if !prefix.Addr().Is4() || prefix.Bits() < 0 || prefix.Bits() > 32 {
		return fmt.Errorf("invalid IPv4 prefix %q", prefix)
	}
	setAddr := func(req uint, addr []byte) error {
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			return err
		}
		if err = ifr.SetInet4Addr(addr); err != nil {
			return err
		}
		return ioctl(req, ifr)
	}
	if err := setAddr(unix.SIOCSIFADDR, prefix.Addr().AsSlice()); err != nil {
		return fmt.Errorf("set IPv4 address: %w", err)
	}
	if err := setAddr(unix.SIOCSIFNETMASK, net.CIDRMask(prefix.Bits(), 32)); err != nil {
		return fmt.Errorf("set IPv4 netmask: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	if err = ioctl(unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}
	ifr, err = unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err = ioctl(unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("get interface flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err = ioctl(unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set interface UP: %w", err)
	}
	return nil
}

func (d *Device) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *Device) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *Device) Close() error                { return d.f.Close() }
