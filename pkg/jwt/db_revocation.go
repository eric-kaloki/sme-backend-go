package jwt

import (
	"log"
	"time"

	"github.com/jmoiron/sqlx"
)

// DbRevocationStore is a persistent token blacklist using PostgreSQL.
// It implements the jwt.Revoker interface.
type DbRevocationStore struct {
	db *sqlx.DB
}

// NewDbRevocationStore creates a new database-backed revocation store.
// It also starts a background task to clean up expired records once every hour.
func NewDbRevocationStore(db *sqlx.DB) *DbRevocationStore {
	store := &DbRevocationStore{db: db}
	go store.runCleanup()
	return store
}

// Revoke adds a token ID (JTI) to the database until its natural expiry.
func (s *DbRevocationStore) Revoke(jti string, expiresAt time.Time) {
	_, err := s.db.Exec(
		"INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING",
		jti, expiresAt,
	)
	if err != nil {
		log.Printf("ERROR: Failed to persist token revocation for JTI %s: %v", jti, err)
	}
}

// IsRevoked checks the database to see if a token has been explicitly logged out.
func (s *DbRevocationStore) IsRevoked(jti string) bool {
	var exists bool
	err := s.db.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1 AND expires_at > NOW())",
		jti,
	).Scan(&exists)
	
	if err != nil {
		// If the DB check fails, we default to "not revoked" to avoid blocking valid users,
		// but we log the error for investigation.
		log.Printf("ERROR: Failed to check token revocation status for JTI %s: %v", jti, err)
		return false
	}
	return exists
}

// runCleanup removes expired entries from the database every hour to keep the table size small.
func (s *DbRevocationStore) runCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		result, err := s.db.Exec("DELETE FROM revoked_tokens WHERE expires_at < NOW()")
		if err != nil {
			log.Printf("ERROR: Failed to clean up expired revoked tokens: %v", err)
			continue
		}
		
		if rows, _ := result.RowsAffected(); rows > 0 {
			log.Printf("INFO: Cleaned up %d expired revoked tokens from database", rows)
		}
	}
}
