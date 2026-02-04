package mfa

import "errors"

var (
	ErrInvalidMFAChallenge error = errors.New("invalid mfa challenge")
)
