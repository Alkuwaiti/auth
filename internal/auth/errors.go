package auth

import "errors"

var (
	ErrUserNotFound                 error = errors.New("user not found")
	ErrSessionNotFound              error = errors.New("session not found")
	ErrUserNotFoundOrAlreadyDeleted error = errors.New("user not found or already deleted")
	ErrInvalidMFAChallenge          error = errors.New("invalid mfa challenge")
	ErrInvalidMFAChallengeType      error = errors.New("invalid mfa challenge type")
	ErrInvalidMFAChallengeScope     error = errors.New("invalid mfa challenge scope")
)
