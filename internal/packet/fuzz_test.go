package packet

import (
	"net/netip"
	"testing"
)

func FuzzIPv4Parser(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		Source(b)
		Destination(b)
	})
}

func FuzzRewriteSource(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		RewriteSourceIPv4(b, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.128"))
	})
}

func FuzzRewriteDestination(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		RewriteDestinationIPv4(b, netip.MustParseAddr("192.0.2.128"), netip.MustParseAddr("192.0.2.2"))
	})
}

func FuzzTranslateICMP(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		TranslateICMP(b, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.128"), true)
		TranslateICMP(b, netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.128"), false)
	})
}
