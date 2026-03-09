package domain

import (
	"time"

	"github.com/google/uuid"
)

// TODO: reduce the fields to only what the service needs.

type User struct {
	ID              uuid.UUID       `json:"id"`
	Email           string          `json:"email"`
	PasswordHash    *string         `json:"Password_hash"`
	IsEmailVerified bool            `json:"is_email_verified"`
	IsActive        bool            `json:"is_active"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	DeletedAt       *time.Time      `json:"deleted_at"`
	DeletionReason  *DeletionReason `json:"deletion_reason"`
	Roles           []string        `json:"roles"`
	MFAEnabled      bool            `json:"mfa_enabled"`
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
