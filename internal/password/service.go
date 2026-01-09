// Package password holds everything password related
package password

import (
	"unicode"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"golang.org/x/crypto/bcrypt"
)

type passwordService struct {
	cost int
}

func NewService(cost int) *passwordService {
	return &passwordService{
		cost,
	}
}

func (p *passwordService) Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	return string(b), err
}

func (p *passwordService) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (p *passwordService) Validate(password string) error {
	runes := []rune(password)

	if len(runes) < 8 {
		return &apperrors.ValidationError{
			Field: "password",
			Msg:   "must be at least 8 characters",
		}
	}

	if len(runes) > 255 {
		return &apperrors.ValidationError{
			Field: "password",
			Msg:   "maximum 255 characters",
		}
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool

	for _, c := range password {
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
