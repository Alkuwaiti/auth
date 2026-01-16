// Package core contains shared application stuff.
package core

import (
	"github.com/golang-jwt/jwt/v5"
)

type EmailKey struct{}

type UserIDKey struct{}

type UserAgentKey struct{}

type IPAddressKey struct{}

type AccessClaims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}
