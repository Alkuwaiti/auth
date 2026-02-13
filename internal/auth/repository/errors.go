package repository

import "errors"

var (
	ErrNotFound error = errors.New("record not found")
)
