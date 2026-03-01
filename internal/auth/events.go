package auth

import "github.com/google/uuid"

type userRegistered struct {
	UserID uuid.UUID
	Email  string
}

func (u userRegistered) eventType() string {
	return "user.registered"
}
