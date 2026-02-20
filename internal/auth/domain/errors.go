package domain

import "errors"

var (
	ErrNotFound            error = errors.New("record not found")
	ErrRecordAlreadyExists error = errors.New("record already exists")
)
