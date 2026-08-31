package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func tcpPacket(src, dst netip.Addr) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], 40)
	b[9] = 6
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	b[20] = 0x50
	binary.BigEndian.PutUint16(b[32:34], 0)
	checksumIPv4(b[:20])
	return b
}
func TestRewriteTCPAndUDPAddresses(t *testing.T) {
	old := netip.MustParseAddr("192.0.2.2")
	newIP := netip.MustParseAddr("192.0.2.128")
	dst := netip.MustParseAddr("8.8.8.8")
	b := tcpPacket(old, dst)
	if !RewriteSourceIPv4(b, old, newIP) {
		t.Fatal("tcp rewrite failed")
	}
	if s, _ := Source(b); s != newIP {
		t.Fatal("tcp source not rewritten")
	}
	if b[10] == 0 && b[11] == 0 {
		t.Fatal("header checksum not updated")
	}
	u := make([]byte, 28)
	u[0] = 0x45
	binary.BigEndian.PutUint16(u[2:4], 28)
	u[9] = 17
	copy(u[12:16], old.AsSlice())
	copy(u[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(u[26:28], 0)
	if !RewriteSourceIPv4(u, old, newIP) || binary.BigEndian.Uint16(u[26:28]) != 0 {
		t.Fatal("UDP zero checksum changed")
	}
}
func TestFragmentAndICMPTranslation(t *testing.T) {
	old := netip.MustParseAddr("192.0.2.2")
	shadow := netip.MustParseAddr("192.0.2.128")
	dst := netip.MustParseAddr("8.8.8.8")
	q := tcpPacket(old, dst)
	q[6] = 0x20
	q[7] = 0
	outer := make([]byte, 20+8+len(q))
	outer[0] = 0x45
	binary.BigEndian.PutUint16(outer[2:4], uint16(len(outer)))
	outer[9] = 1
	copy(outer[16:20], shadow.AsSlice())
	outer[20] = 3
	outer[21] = 4
	copy(outer[28:], q)
	checksumIPv4(outer[:20])
	if !TranslateICMP(outer, old, shadow, false) {
		t.Fatal("ICMP translation failed")
	}
	if d, _ := Destination(outer); d != old {
		t.Fatal("outer destination not translated")
	}
	if s, _ := Source(outer[28:]); s != old {
		t.Fatal("quoted source not translated")
	}
}
