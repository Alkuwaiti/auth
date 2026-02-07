package mfa

import "errors"

var (
	ErrInvalidMFAChallenge      error = errors.New("invalid mfa challenge")
	ErrInvalidMFAChallengeType  error = errors.New("invalid mfa challenge type")
	ErrInvalidMFAChallengeScope error = errors.New("invalid mfa challenge scope")
)
