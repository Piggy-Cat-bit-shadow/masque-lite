package session

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
)

type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) ([]byte, error)
	Close() error
}
type Session struct {
	ID         uint64
	ClientIP   netip.Addr
	VisibleIP  netip.Addr
	ShadowIP   netip.Addr
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
	return &Session{ClientIP: ip, VisibleIP: ip, Identity: identity, Conn: conn, Ctx: ctx, Cancel: cancel, Outbound: make(chan []byte, 128), onClose: onClose}
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
	mu               sync.RWMutex
	sessions         map[netip.Addr]*Session
	sessionsByShadow map[netip.Addr]*Session
	sessionsByID     map[uint64]*Session
	next             uint64
	shadow           bool
	shadowPool       netip.Prefix
	shadowNext       netip.Addr
	max              int
	excluded         map[netip.Addr]bool
}

func NewManager() *Manager { return &Manager{sessions: map[netip.Addr]*Session{}} }
func NewShadowManager(pool netip.Prefix, max int, excluded []netip.Addr) *Manager {
	pool = pool.Masked()
	m := NewManager()
	m.shadow = true
	m.shadowPool = pool
	m.shadowNext = pool.Addr()
	m.max = max
	m.sessionsByShadow = map[netip.Addr]*Session{}
	m.sessionsByID = map[uint64]*Session{}
	m.excluded = map[netip.Addr]bool{}
	for _, ip := range excluded {
		m.excluded[ip] = true
	}
	return m
}
func (m *Manager) Register(s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.shadow {
		return fmt.Errorf("shadow allocator disabled")
	}
	if len(m.sessionsByID) >= m.max {
		return fmt.Errorf("session capacity exhausted")
	}
	ip, ok := m.allocateLocked()
	if !ok {
		return fmt.Errorf("shadow address pool exhausted")
	}
	m.next++
	s.ID = m.next
	s.Generation = m.next
	s.ShadowIP = ip
	m.sessionsByID[s.ID] = s
	m.sessionsByShadow[ip] = s
	return nil
}
func (m *Manager) allocateLocked() (netip.Addr, bool) {
	count := uint64(1) << uint(32-m.shadowPool.Bits())
	last := m.shadowPool.Addr()
	for i := uint64(1); i < count; i++ {
		last = last.Next()
	}
	for i := uint64(0); i < count; i++ {
		ip := m.shadowNext
		if !m.shadowPool.Contains(ip) {
			ip = m.shadowPool.Addr()
		}
		m.shadowNext = ip.Next()
		if m.shadowPool.Contains(m.shadowNext) == false {
			m.shadowNext = m.shadowPool.Addr()
		}
		if ip == m.shadowPool.Addr() || ip == last || m.excluded[ip] || m.sessionsByShadow[ip] != nil {
			continue
		}
		return ip, true
	}
	return netip.Addr{}, false
}
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
	if m.shadow {
		if m.sessionsByID[s.ID] != s {
			return false
		}
		delete(m.sessionsByID, s.ID)
		delete(m.sessionsByShadow, s.ShadowIP)
		return true
	}
	if m.sessions[s.ClientIP] != s {
		return false
	}
	delete(m.sessions, s.ClientIP)
	return true
}
func (m *Manager) Lookup(ip netip.Addr) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shadow {
		return m.sessionsByShadow[ip]
	}
	return m.sessions[ip]
}
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.shadow {
		return len(m.sessionsByID)
	}
	return len(m.sessions)
}
func (m *Manager) Snapshot() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.sessions)
	if m.shadow {
		n = len(m.sessionsByID)
	}
	out := make([]*Session, 0, n)
	if m.shadow {
		for _, s := range m.sessionsByID {
			out = append(out, s)
		}
	} else {
		for _, s := range m.sessions {
			out = append(out, s)
		}
	}
	return out
}
func (m *Manager) IsShadow() bool { m.mu.RLock(); defer m.mu.RUnlock(); return m.shadow }
