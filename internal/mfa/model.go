package mfa

import (
	"time"

	"github.com/google/uuid"
)

type MFAMethod struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Type        MFAMethodType
	Secret      string
	ConfirmedAt *time.Time
}

type MFAChallenge struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	MethodID      uuid.UUID
	ChallengeType ChallengeType
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
}
