package auth

import "errors"

var (
	ErrUserNotFound = errors.New("user not found")

	ErrSessionNotFound = errors.New("session not found")

	ErrUserNotFoundOrAlreadyDeleted = errors.New("user not found or already deleted")
)
