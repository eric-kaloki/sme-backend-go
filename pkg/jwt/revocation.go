package jwt

import (
	"sync"
	"time"
)

// RevokedToken records a revoked JTI and when it naturally expires.
// We only need to keep revoked JTIs until their natural expiry —
// after that the token would be rejected by expiry check anyway.
type revokedEntry struct {
	expiresAt time.Time
}

// RevocationStore is an in-memory token blacklist.
//
// Design decision: in-memory is sufficient for a single-instance Render
// deployment. If the system is ever scaled to multiple instances, replace
// this with a Redis-backed store using the same interface — the auth
// middleware depends only on the Revoker interface below.
//
// The store runs a background cleanup goroutine to prevent unbounded growth.
type RevocationStore struct {
	mu      sync.RWMutex
	entries map[string]revokedEntry
}

// Revoker is the interface the auth middleware depends on.
// Keep it narrow — callers only need Revoke and IsRevoked.
type Revoker interface {
	Revoke(jti string, expiresAt time.Time)
	IsRevoked(jti string) bool
}
// Revoke adds a JTI to the blacklist until its natural expiry.
func (s *RevocationStore) Revoke(jti string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[jti] = revokedEntry{expiresAt: expiresAt}
}

// IsRevoked returns true if the JTI has been explicitly revoked.
func (s *RevocationStore) IsRevoked(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, exists := s.entries[jti]
	if !exists {
		return false
	}
	// If the entry has naturally expired, treat it as not-revoked
	// (the token would fail expiry validation anyway).
	return time.Now().Before(entry.expiresAt)
}

// runCleanup removes expired entries every 10 minutes to prevent
// unbounded memory growth.
func (s *RevocationStore) runCleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.purgeExpired()
	}
}

func (s *RevocationStore) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for jti, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, jti)
		}
	}
}
