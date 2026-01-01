// Package core contains shared application stuff.
package core

import (
	"github.com/golang-jwt/jwt/v5"
)

type EmailKey struct{}

type AccessClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}
