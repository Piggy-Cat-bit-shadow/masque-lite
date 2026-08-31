package session

import (
	"errors"
	"net/netip"
	"testing"
)

type fakeConn struct{ closed int }

func (f *fakeConn) ReadPacket() ([]byte, error)        { return nil, errors.New("closed") }
func (f *fakeConn) WritePacket([]byte) ([]byte, error) { return nil, nil }
func (f *fakeConn) Close() error                       { f.closed++; return nil }
func TestManagerConcurrentIPsAndTakeover(t *testing.T) {
	m := NewManager()
	a := New(netip.MustParseAddr("192.0.2.2"), "a", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
	b := New(netip.MustParseAddr("192.0.2.3"), "b", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
	m.Replace(a)
	m.Replace(b)
	if m.Len() != 2 {
		t.Fatal(m.Len())
	}
	a2 := New(a.ClientIP, "a2", &fakeConn{}, func(s *Session) { m.RemoveIfCurrent(s) })
	m.Replace(a2)
	if m.Lookup(a.ClientIP) != a2 || m.Lookup(b.ClientIP) != b {
		t.Fatal("replace damaged registry")
	}
	if m.RemoveIfCurrent(a) {
		t.Fatal("stale remove succeeded")
	}
	if m.Lookup(a.ClientIP) != a2 {
		t.Fatal("stale removal deleted new session")
	}
	a2.Close()
	b.Close()
}

func TestManagerQueueIsBounded(t *testing.T) {
	m := NewManager()
	s := New(netip.MustParseAddr("192.0.2.2"), "a", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	m.Replace(s)
	for i := 0; i < cap(s.Outbound); i++ {
		s.Outbound <- []byte{1}
	}
	select {
	case s.Outbound <- []byte{2}:
		t.Fatal("queue accepted packet beyond capacity")
	default:
	}
	s.Close()
}
