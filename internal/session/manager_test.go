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

func TestShadowManagerAllowsSameVisibleIP(t *testing.T) {
	pool := netip.MustParsePrefix("192.0.2.128/30")
	m := NewShadowManager(pool, 2, nil)
	a := New(netip.MustParseAddr("192.0.2.2"), "a", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	b := New(netip.MustParseAddr("192.0.2.2"), "b", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := m.Register(b); err != nil {
		t.Fatal(err)
	}
	if a.ShadowIP == b.ShadowIP || m.Len() != 2 {
		t.Fatalf("shadow sessions = %s, %s; len=%d", a.ShadowIP, b.ShadowIP, m.Len())
	}
	if m.Lookup(a.ShadowIP) != a || m.Lookup(b.ShadowIP) != b {
		t.Fatal("shadow lookup mismatch")
	}
	a.Close()
	if m.Lookup(a.ShadowIP) != nil || m.Lookup(b.ShadowIP) != b {
		t.Fatal("closing A affected B")
	}
	c := New(netip.MustParseAddr("192.0.2.2"), "c", &fakeConn{}, func(x *Session) { m.RemoveIfCurrent(x) })
	if err := m.Register(c); err != nil {
		t.Fatal(err)
	}
	c.Close()
	b.Close()
}
