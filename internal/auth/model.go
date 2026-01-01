package auth

import (
	"time"

	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	RefreshExpiresAt time.Time
	UserID           uuid.UUID
}

type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	RefreshToken     string
	UserAgent        string
	IPAddress        string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason RevocationReason
	CompromisedAt    *time.Time
}

func (s *Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}
