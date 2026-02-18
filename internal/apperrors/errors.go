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

type DuplicateError struct {
	Resource string
	Field    string
	Value    string
}

func (e *DuplicateError) Error() string {
	// NOTE: intentionally left with no data.
	return "invalid credentials"
}

type InternalError struct {
	Msg string
	Err error
}

func (e *InternalError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	}
	return e.Msg
}

type BadRequestError struct {
	Field string
	Msg   string
}

func (e *BadRequestError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Msg)
}
