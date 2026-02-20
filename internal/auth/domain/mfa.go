// Package domain contains domain models.
package domain

import (
	"time"

	"github.com/google/uuid"
)

type MFABackupCode struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	CodeHash   string
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

type MFAChallenge struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	MethodID      uuid.UUID
	Scope         ChallengeScope
	ChallengeType ChallengeType
	ExpiresAt     time.Time
	ConsumedAt    *time.Time
	Attempts      int
}

type ActiveTOTPChallenge struct {
	ChallengeID      uuid.UUID
	UserID           uuid.UUID
	MethodID         uuid.UUID
	Attempts         int
	SecretCiphertext []byte
}

type ChallengeType string

const (
	ChallengeLogin  ChallengeType = "login"
	ChallengeStepUp ChallengeType = "step_up"
)

func (c ChallengeType) String() string {
	return string(c)
}

type ChallengeScope string

const (
	ScopeLogin          ChallengeScope = "login"
	ScopeDeleteAccount  ChallengeScope = "delete_account"
	ScopeChangePassword ChallengeScope = "change_password"
)

func (c ChallengeScope) String() string {
	return string(c)
}

type MFAMethodType string

const (
	MFAMethodTOTP MFAMethodType = "totp"
)

func (t MFAMethodType) IsValid() bool {
	switch t {
	case MFAMethodTOTP:
		return true
	default:
		return false
	}
}

func (t MFAMethodType) String() string {
	return string(t)
}

type MFAMethod struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Type            MFAMethodType
	ConfirmedAt     *time.Time
	EncryptedSecret string
	CreatedAt       time.Time
	ExpiresAt       *time.Time
}
