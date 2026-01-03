// Package password holds everything password related
package password

import (
	"unicode"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"golang.org/x/crypto/bcrypt"
)

type bcryptPasswordService struct {
	cost int
}

func NewService(cost int) *bcryptPasswordService {
	return &bcryptPasswordService{
		cost,
	}
}

func (p *bcryptPasswordService) Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	return string(b), err
}

func (p *bcryptPasswordService) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (p *bcryptPasswordService) Validate(password string) error {
	if len(password) < 8 {
		return &apperrors.ValidationError{Field: "username", Msg: "must be at least 8 characters"}
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
