package user

import (
	"errors"
	"net/mail"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID `json:"id"`
	Email           string    `json:"email"`
	Username        string    `json:"username"`
	PasswordHash    string    `json:"password_hash"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type RegisterUserInput struct {
	username, email, password string
}

func (r *RegisterUserInput) validate() error {
	err := r.validateEmail()
	if err != nil {
		return err
	}

	err = r.validateUsername()
	if err != nil {
		return err
	}

	err = r.validatePassword()
	if err != nil {
		return err
	}

	return nil
}

func (r *RegisterUserInput) validateEmail() error {
	r.email = strings.TrimSpace(r.email)

	if r.email == "" {
		return errors.New("email cannot be empty")
	}

	if _, err := mail.ParseAddress(r.email); err != nil {
		return errors.New("email has an invalid format")
	}

	return nil
}

func (r *RegisterUserInput) validateUsername() error {
	r.username = strings.TrimSpace(r.username)

	if r.username == "" {
		return errors.New("username cannot be empty")
	}

	if len(r.username) < 3 {
		return errors.New("username must be at least 3 characters")
	}

	if len(r.username) > 50 {
		return errors.New("username must not exceed 50 characters")
	}

	return nil
}

func (r *RegisterUserInput) validatePassword() error {
	if len(r.password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, c := range r.password {
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
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}
