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

type userEmailVerificationRequested struct {
	UserID uuid.UUID
	Email  string
	Token  string
}

type userVerifiedEmail struct {
	UserID uuid.UUID
	Email  string
}
