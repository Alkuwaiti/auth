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
	if _, err := mail.ParseAddress(strings.TrimSpace(r.Email)); err != nil {
		return ErrInvalidEmail
	}

	return nil
}

func (r *RegisterUserInput) validateUsername() error {
	r.Username = strings.TrimSpace(r.Username)

	if r.Username == "" {
		return ErrUsernameEmpty
	}

	if len(r.Username) < 3 {
		return ErrUsernameTooShort
	}

	if len(r.Username) > 50 {
		return ErrUsernameTooLong
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
