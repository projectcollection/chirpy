package storage

import (
	"time"
)

func (db *DB) RevokeRFToken(token string) {
	db.db.RevokedRFTokens[token] = time.Now()
}

func (db *DB) IsRFTokenRevoked(token string) bool {
	_, ok := db.db.RevokedRFTokens[token]

	return ok
}
