//go:build linux

package tunnel

import (
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
