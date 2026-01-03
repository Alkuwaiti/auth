// Package security provides security methods.
package security

import (
	"unicode"

	"github.com/alkuwaiti/auth/internal/apperrors"
)

func ValidatePassword(password string) error {
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
