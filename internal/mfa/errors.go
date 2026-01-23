package mfa

import "errors"

var (
	ErrInvalidMFAMethodType      = errors.New("invalid mfa type")
	ErrMFAMethodAlreadyEnrolled  = errors.New("user already enrolled in this mfa method")
	ErrMFAMethodAlreadyConfirmed = errors.New("mfa method already confirmed")
	ErrInvalidOTP                = errors.New("invalid otp")
)
