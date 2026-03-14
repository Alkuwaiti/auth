// Package passwords holds everything password related
package passwords

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func Hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}

func Compare(hash, password string) (bool, error) {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func Validate(password string) error {
	runes := []rune(password)

	if len(runes) < 8 {
		return ErrPasswordTooShort
	}

	if len(runes) > 255 {
		return ErrPasswordTooLong
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
		return ErrPasswordMissingUppercase
	}
	if !hasLower {
		return ErrPasswordMissingLowercase
	}
	if !hasNumber {
		return ErrPasswordMissingNumber
	}
	if !hasSpecial {
		return ErrPasswordMissingSpecial
	}

	return nil
}
