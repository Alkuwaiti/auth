package googlesocial

import "errors"

var (
	ErrInvalidState          = errors.New("invalid state format")
	ErrInvalidStateSignature = errors.New("invalid state signature")
	ErrStateExpired          = errors.New("state expired")
)
