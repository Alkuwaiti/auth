package core

import "errors"

var (
	ErrUserNotFound = errors.New("user not found")

	ErrSessionNotFound = errors.New("session not found")

	ErrUserNotFoundOrAlreadyDeleted = errors.New("User not found or already deleted")
)
