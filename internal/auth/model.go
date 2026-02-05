package auth

import (
	"net/mail"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/mfa"
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

type RegisterUserInput struct {
	Username, Email, Password string
}

func (r *RegisterUserInput) validate() error {
	if err := r.validateEmail(); err != nil {
		return err
	}

	if err := r.validateUsername(); err != nil {
		return err
	}

	if err := r.validatePassword(); err != nil {
		return err
	}

	return nil
}

func (r *RegisterUserInput) validateEmail() error {
	r.Email = strings.TrimSpace(r.Email)

	if r.Email == "" {
		return &apperrors.ValidationError{Field: "email", Msg: "cannot be empty"}
	}

	if _, err := mail.ParseAddress(r.Email); err != nil {
		return &apperrors.ValidationError{Field: "email", Msg: "email has an invalid format"}
	}

	return nil
}

func (r *RegisterUserInput) validateUsername() error {
	r.Username = strings.TrimSpace(r.Username)

	if r.Username == "" {
		return &apperrors.ValidationError{Field: "username", Msg: "cannot be empty"}
	}

	if len(r.Username) < 3 {
		return &apperrors.ValidationError{Field: "username", Msg: "must be at least 3 characters"}
	}

	if len(r.Username) > 50 {
		return &apperrors.ValidationError{Field: "username", Msg: "must not exceed 50 characters"}
	}

	return nil
}

func (r *RegisterUserInput) validatePassword() error {
	return nil
}

type DeleteUserInput struct {
	UserID         uuid.UUID
	DeletionReason DeletionReason
	ActorID        uuid.UUID
	Note           string
}

func (d *DeleteUserInput) validate() error {
	if err := d.DeletionReason.Validate(); err != nil {
		return err
	}

	return nil
}

type User struct {
	ID              uuid.UUID       `json:"id"`
	Email           string          `json:"email"`
	Username        string          `json:"Username"`
	PasswordHash    string          `json:"Password_hash"`
	IsEmailVerified bool            `json:"is_email_verified"`
	IsActive        bool            `json:"is_active"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	DeletedAt       *time.Time      `json:"deleted_at"`
	DeletionReason  *DeletionReason `json:"deletion_reason"`
	Roles           []string        `json:"roles"`
	MFAEnabled      bool            `json:"mfa_enabled"`
}

type LoginResult struct {
	RequiresMFA bool
	ChallengeID *uuid.UUID
	Tokens      *TokenPair
}

type CreateStepUpChallengeResponse struct {
	ChallengeID   uuid.UUID
	MFAMethodType mfa.MFAMethodType
	ExpiresAt     time.Time
}

type VerifyStepUpChallengeResponse struct {
	StepUpToken string
	ExpiresIn   time.Time
}
