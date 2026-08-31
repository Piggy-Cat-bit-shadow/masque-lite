//go:build linux

package tunnel

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewIfreq(t *testing.T) {
	ifr, err := newIfreq("masque0")
	if err != nil {
		t.Fatal(err)
	}
	if ifr.Name() != "masque0" {
		t.Fatalf("name = %q", ifr.Name())
	}
	if ifr.Uint16() != unix.IFF_TUN|unix.IFF_NO_PI {
		t.Fatalf("flags = %#x", ifr.Uint16())
	}
}

func TestConfigureInterfaceIsRepeatable(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.1/30")
	for i := 0; i < 2; i++ {
		var calls []struct {
			req uint
			ifr unix.Ifreq
		}
		err := configureInterface("masque0", prefix, 1280, func(req uint, ifr *unix.Ifreq) error {
			if req == unix.SIOCGIFFLAGS {
				ifr.SetUint16(unix.IFF_MULTICAST)
			}
			calls = append(calls, struct {
				req uint
				ifr unix.Ifreq
			}{req, *ifr})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(calls) != 5 {
			t.Fatalf("ioctl calls = %d, want 5", len(calls))
		}
		if calls[0].req != unix.SIOCSIFADDR || calls[1].req != unix.SIOCSIFNETMASK || calls[2].req != unix.SIOCSIFMTU || calls[3].req != unix.SIOCGIFFLAGS || calls[4].req != unix.SIOCSIFFLAGS {
			t.Fatal("unexpected ioctl sequence")
		}
		address, _ := calls[0].ifr.Inet4Addr()
		if got := netip.AddrFrom4([4]byte(address)); got != prefix.Addr() {
			t.Fatalf("address = %s", got)
		}
		if calls[2].ifr.Uint32() != 1280 {
			t.Fatalf("MTU = %d", calls[2].ifr.Uint32())
		}
		if calls[4].ifr.Uint16()&unix.IFF_UP == 0 {
			t.Fatal("interface is not UP")
		}
	}
}
