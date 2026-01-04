// Package coreerrors provides core errors
package coreerrors

import "errors"

var ErrUserNotFound = errors.New("user not found")

var ErrSessionNotFound = errors.New("session not found")
