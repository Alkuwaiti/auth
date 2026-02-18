package auth

import "errors"

var (
	ErrForbidden                      = errors.New("forbidden")
	ErrInvalidCredentials             = errors.New("invalid credentials")
	ErrPasswordReuse                  = errors.New("new password cannot be old password")
	ErrRefreshDisabled                = errors.New("refresh tokens disabled by system")
	ErrChallengeExpired               = errors.New("challenge expired")
	ErrInvalidMFACode                 = errors.New("incorrect mfa code")
	ErrInvalidMFAChallenge      error = errors.New("invalid mfa challenge")
	ErrInvalidMFAChallengeType  error = errors.New("invalid mfa challenge type")
	ErrInvalidMFAChallengeScope error = errors.New("invalid mfa challenge scope")
)
