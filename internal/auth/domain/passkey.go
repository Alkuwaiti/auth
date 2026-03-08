package domain

import (
	"time"

	"github.com/google/uuid"
)

type WebAuthnChallenge struct {
	Challenge []byte
	UserID    uuid.UUID
	ExpiresAt time.Time
}
