package auth

import (
	"time"

	"github.com/google/uuid"
)

type userRegistered struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
}

type userDeleted struct {
	UserID uuid.UUID `json:"user_id"`
	Reason string    `json:"reason"`
}

type userEmailVerificationRequested struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
	Token  string    `json:"token"`
}

type userVerifiedEmail struct {
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
}

type userForgetPassword struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type userChangePassword struct {
	Email     string    `json:"email"`
	ChangedAt time.Time `json:"changed_at"`
}
