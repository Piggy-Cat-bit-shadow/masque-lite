//go:build linux

package tunnel

import (
	"fmt"
	"golang.org/x/sys/unix"
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
func (d *Device) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *Device) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *Device) Close() error                { return d.f.Close() }
