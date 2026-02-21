package auth

import "errors"

var (
	ErrForbidden                = errors.New("forbidden")
	ErrUserExists               = errors.New("user exists")
	ErrUserNotFound             = errors.New("user not found")
	ErrInvalidCredentials       = errors.New("invalid credentials")
	ErrPasswordReuse            = errors.New("new password cannot be old password")
	ErrRefreshDisabled          = errors.New("refresh tokens disabled by system")
	ErrChallengeExpired         = errors.New("challenge expired")
	ErrChallengeConsumed        = errors.New("challenge already consumed")
	ErrInvalidMFACode           = errors.New("incorrect mfa code")
	ErrInvalidMFAChallenge      = errors.New("invalid mfa challenge")
	ErrInvalidMFAChallengeType  = errors.New("invalid mfa challenge type")
	ErrInvalidMFAMethodType     = errors.New("invalid mfa method type")
	ErrInvalidMFAChallengeScope = errors.New("invalid mfa challenge scope")
	ErrMFAMethodAlreadyEnrolled = errors.New("MFA method already enrolled")
	ErrMFAMethodExpired         = errors.New("method enrollment window expired")
	ErrMethodAlreadyConfirmed   = errors.New("already confirmed")
	ErrInvalidEmail             = errors.New("invalid email")
	ErrUsernameEmpty            = errors.New("username empty")
	ErrUsernameTooShort         = errors.New("username must be at least 3 characters")
	ErrUsernameTooLong          = errors.New("username must not exceed 50 characters")
	ErrInvalidDeletionReason    = errors.New("invalid deletion reason")
	ErrInvalidResetToken        = errors.New("invalid reset token")
)
