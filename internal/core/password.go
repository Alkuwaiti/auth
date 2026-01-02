package core

import (
	"unicode"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedBytes), nil
}

func VerifyPassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hashedPassword),
		[]byte(password),
	)
	return err == nil
}

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
