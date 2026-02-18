// Package apperrors provides app wide errors to be re-used.
package apperrors

// TODO: this probably needs a revamp

import "fmt"

type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Msg)
}
