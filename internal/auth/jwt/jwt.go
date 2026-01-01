// Package jwt contains JWT-specific token structures.
package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type EmailKey struct{}

type AccessClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}
