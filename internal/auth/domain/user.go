package domain

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID              uuid.UUID  `json:"id"`
	Email           string     `json:"email"`
	PasswordHash    *string    `json:"Password_hash"`
	IsEmailVerified bool       `json:"is_email_verified"`
	IsActive        bool       `json:"is_active"`
	DeletedAt       *time.Time `json:"deleted_at"`
	Roles           []string   `json:"roles"`
}

type DeletionReason string

const (
	DeletionUserBot     DeletionReason = "USER_IS_BOT"
	DeletionUserRequest DeletionReason = "USER_REQUEST"
	DeletionAdminAction DeletionReason = "ADMIN_ACTION"
)

func (d DeletionReason) IsValid() bool {
	switch d {
	case DeletionUserBot, DeletionUserRequest, DeletionAdminAction:
		return true
	default:
		return false
	}
}

func (d DeletionReason) String() string {
	return string(d)
}
