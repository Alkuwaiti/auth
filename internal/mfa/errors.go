package mfa

import "errors"

var (
	ErrInvalidMFAMethodType     = errors.New("invalid mfa type")
	ErrMFAMethodAlreadyEnrolled = errors.New("user already enrolled in this mfa method")
)
