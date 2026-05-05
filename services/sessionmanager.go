package services

import "sync"

type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	resolver *Resolver
}

func NewSessionManager(rs *Resolver) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		resolver: rs,
	}
}

func (sm *SessionManager) NewSession() *Session {
	sm.mu.Lock()
	session := NewSession(sm.resolver)
	for sm.sessions[session.ID] != nil {
		session = NewSession(sm.resolver)
	}
	sm.sessions[session.ID] = session
	sm.mu.Unlock()
	return session
}

func (sm *SessionManager) EndSession(session *Session) {
	sm.mu.Lock()
	delete(sm.sessions, session.ID)
	sm.mu.Unlock()
}
