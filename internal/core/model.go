// Package core contains shared application stuff.
package core

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type EmailKey struct{}

type UserIDKey struct{}

type UserAgentKey struct{}

type IPAddressKey struct{}

type AccessClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type User struct {
	ID              uuid.UUID       `json:"id"`
	Email           string          `json:"email"`
	Username        string          `json:"Username"`
	PasswordHash    string          `json:"Password_hash"`
	IsEmailVerified bool            `json:"is_email_verified"`
	IsActive        bool            `json:"is_active"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	DeletedAt       *time.Time      `json:"deleted_at"`
	DeletionReason  *DeletionReason `json:"deletion_reason"`
}
