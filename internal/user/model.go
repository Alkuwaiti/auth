package user

import (
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"Username"`
	PasswordHash    string    `json:"Password_hash"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
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
	if len(r.Password) < 8 {
		return &apperrors.ValidationError{Field: "username", Msg: "must be at least 8 characters"}
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, c := range r.Password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return &apperrors.ValidationError{Field: "password", Msg: "must contain at least one uppercase letter"}
	}
	if !hasLower {
		return &apperrors.ValidationError{Field: "password", Msg: "must contain at least one lowercase letter"}
	}
	if !hasNumber {
		return &apperrors.ValidationError{Field: "password", Msg: "must contain at least one number"}
	}
	if !hasSpecial {
		return &apperrors.ValidationError{Field: "password", Msg: "must contain at least one special character"}
	}

	return nil
}
