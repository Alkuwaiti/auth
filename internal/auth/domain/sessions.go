package domain

import (
	"time"

	"github.com/google/uuid"
)

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

type RotateSessionInput struct {
	OldSessionID     uuid.UUID
	UserID           uuid.UUID
	Expiry           time.Time
	RevocationReason RevocationReason
	RefreshToken     string
	IPAddress        string
	UserAgent        string
}
