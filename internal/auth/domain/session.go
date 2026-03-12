package domain

import (
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevocationReason RevocationReason
	CompromisedAt    *time.Time
}

func (s *Session) IsExpired() bool {
	return s.ExpiresAt.Before(time.Now())
}

type RevocationReason string

const (
	RevocationSessionCompromised RevocationReason = "user session compromised"
	RevocationSessionRotation    RevocationReason = "rotated session"
	RevocationLogout             RevocationReason = "logout"
	RevocationPasswordChange     RevocationReason = "password changed"
	RevocationUserDeleted        RevocationReason = "user deleted"
)

func (r RevocationReason) String() string {
	return string(r)
}
