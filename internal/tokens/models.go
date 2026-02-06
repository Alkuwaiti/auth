// Package tokens provides jwt stuff.
package tokens

import "github.com/golang-jwt/jwt/v5"

type AccessClaims struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
	Type  string   `json:"type"`
	jwt.RegisteredClaims
}

type StepUpClaims struct {
	Email string `json:"email"`
	Scope string `json:"scope"`
	Type  string `json:"type"`
	jwt.RegisteredClaims
}

type Config struct {
	JWTKey   []byte
	Issuer   string
	Audience string
}
