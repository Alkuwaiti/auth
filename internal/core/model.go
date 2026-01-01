// Package core contains shared application stuff.
package core

import (
	"github.com/golang-jwt/jwt/v5"
)

type UserIDKey struct{}

type AccessClaims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}
