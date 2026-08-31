package session

import (
	"context"
	"net/netip"
	"sync"
)

type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}

type Session struct {
	ClientIP   netip.Addr
	Identity   string
	Conn       PacketConn
	Ctx        context.Context
	Cancel     context.CancelFunc
	Generation uint64
	Outbound   chan []byte
	closeOnce  sync.Once
	onClose    func(*Session)
}

func New(ip netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	return NewWithContext(context.Background(), ip, identity, conn, onClose)
}
func NewWithContext(parent context.Context, ip netip.Addr, identity string, conn PacketConn, onClose func(*Session)) *Session {
	ctx, cancel := context.WithCancel(parent)
	return &Session{ClientIP: ip, Identity: identity, Conn: conn, Ctx: ctx, Cancel: cancel, Outbound: make(chan []byte, 128), onClose: onClose}
}
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.Cancel()
		_ = s.Conn.Close()
		if s.onClose != nil {
			s.onClose(s)
		}
	})
}

type Manager struct {
	mu       sync.RWMutex
	sessions map[netip.Addr]*Session
	next     uint64
}

func NewManager() *Manager { return &Manager{sessions: make(map[netip.Addr]*Session)} }
func (m *Manager) Replace(s *Session) (old *Session) {
	m.mu.Lock()
	m.next++
	s.Generation = m.next
	old = m.sessions[s.ClientIP]
	m.sessions[s.ClientIP] = s
	m.mu.Unlock()
	if old != nil && old != s {
		old.Close()
	}
	return old
}
func (m *Manager) RemoveIfCurrent(s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[s.ClientIP] != s {
		return false
	}
	delete(m.sessions, s.ClientIP)
	return true
}
func (m *Manager) Lookup(ip netip.Addr) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[ip]
}
func (m *Manager) Len() int { m.mu.RLock(); defer m.mu.RUnlock(); return len(m.sessions) }
func (m *Manager) Snapshot() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}
