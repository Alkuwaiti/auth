package auth

import "github.com/google/uuid"

type userRegistered struct {
	UserID uuid.UUID
	Email  string
}

type userDeleted struct {
	UserID uuid.UUID
	Reason string
}
