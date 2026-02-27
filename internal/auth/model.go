package auth

import (
	"net/mail"
	"strings"
	"time"

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
	Email, Password string
}

func (r *RegisterUserInput) validate() error {
	if err := r.validateEmail(); err != nil {
		return err
	}

	if err := r.validatePassword(); err != nil {
		return err
	}

	return nil
}

func (r *RegisterUserInput) validateEmail() error {
	if _, err := mail.ParseAddress(strings.TrimSpace(r.Email)); err != nil {
		return ErrInvalidEmail
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
		return ErrInvalidDeletionReason
	}

	return nil
}
