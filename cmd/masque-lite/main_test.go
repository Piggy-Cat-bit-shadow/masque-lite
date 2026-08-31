package main

import "testing"

func TestProtocolForParse(t *testing.T) {
	for _, protocol := range []string{"connect-ip", "cf-connect-ip"} {
		got, ok := protocolForParse(protocol)
		if !ok || got != "connect-ip" {
			t.Fatalf("%q: got (%q, %t), want (connect-ip, true)", protocol, got, ok)
		}
	}
	if got, ok := protocolForParse("connect-udp"); ok || got != "" {
		t.Fatalf("unexpected protocol acceptance: (%q, %t)", got, ok)
	}
}

func TestIPv4PacketValidation(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	copy(pkt[12:16], []byte{10, 89, 0, 2})
	copy(pkt[16:20], []byte{8, 8, 8, 8})
	if src, ok := ipv4Source(pkt); !ok || src.String() != "192.0.2.2" {
		t.Fatalf("source = %s, ok = %t", src, ok)
	}
	if dst, ok := ipv4Destination(pkt); !ok || dst.String() != "8.8.8.8" {
		t.Fatalf("destination = %s, ok = %t", dst, ok)
	}
	for _, bad := range [][]byte{nil, make([]byte, 19), []byte{0x60, 0, 0, 0}, append([]byte{0x41}, make([]byte, 19)...)} {
		if _, ok := ipv4Destination(bad); ok {
			t.Fatal("malformed/non-IPv4 packet accepted")
		}
	}
}
