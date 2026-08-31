//go:build linux

package tunnel

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"unsafe"
)

const (
	tunSetIFF = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
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
	var ifr [unix.IFNAMSIZ]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ-2])) = iffTun | iffNoPI
	_, _, e = unix.Syscall(unix.SYS_IOCTL, f.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if e != unix.Errno(0) {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", e)
	}
	return &Device{f: f, Name: string(ifr[:len(name)]), MTU: mtu}, nil
}
func (d *Device) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *Device) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *Device) Close() error                { return d.f.Close() }
