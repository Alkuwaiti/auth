package auth

import (
	"net/mail"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	RefreshExpiresAt time.Time
	UserID           uuid.UUID
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
	DeletionReason domain.DeletionReason
	ActorID        uuid.UUID
	Note           string
}

func (d *DeleteUserInput) validate() error {
	if !d.DeletionReason.IsValid() {
		return &apperrors.ValidationError{
			Field: "deletion reason",
			Msg:   "invalid deletion reason",
		}

	}

	return nil
}
