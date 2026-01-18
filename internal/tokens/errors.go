package tokens

import "errors"

var (
	ErrSigningMethod error = errors.New("unexpected signing method")
	ErrInvalidToken  error = errors.New("invalid token")
)
