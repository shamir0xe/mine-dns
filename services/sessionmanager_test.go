package services

import (
	"sync"
	"testing"
)

func newTestSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		resolver: newTestResolver(),
	}
}

func TestSessionManager_NewSession(t *testing.T) {
	sm := newTestSessionManager()
	session := sm.NewSession()
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	sm.mu.Lock()
	_, ok := sm.sessions[session.ID]
	sm.mu.Unlock()
	if !ok {
		t.Error("session not stored after NewSession")
	}
}

func TestSessionManager_EndSession(t *testing.T) {
	sm := newTestSessionManager()
	session := sm.NewSession()
	sm.EndSession(session)
	sm.mu.Lock()
	_, ok := sm.sessions[session.ID]
	sm.mu.Unlock()
	if ok {
		t.Error("session still present after EndSession")
	}
}

func TestSessionManager_UniqueIDs(t *testing.T) {
	sm := newTestSessionManager()
	ids := make(map[string]bool)
	for range 50 {
		s := sm.NewSession()
		if ids[s.ID] {
			t.Errorf("duplicate session ID: %s", s.ID)
		}
		ids[s.ID] = true
		sm.EndSession(s)
	}
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	sm := newTestSessionManager()
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			s := sm.NewSession()
			sm.EndSession(s)
		})
	}
	wg.Wait()
	sm.mu.Lock()
	remaining := len(sm.sessions)
	sm.mu.Unlock()
	if remaining != 0 {
		t.Errorf("expected 0 sessions after all ended, got %d", remaining)
	}
}
