package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Manager struct {
	config Config
}

func New(cfg Config) *Manager {
	return &Manager{
		config: cfg,
	}
}

func (m *Manager) GenerateAccessToken(roles []string, userID, email string) (string, error) {

	claims := AccessClaims{
		Email: email,
		Roles: roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.config.Issuer,
			Audience:  jwt.ClaimStrings{m.config.Audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.config.JWTKey)
}

func (m *Manager) ValidateJWT(tokenStr string) (*AccessClaims, error) {

	token, err := jwt.ParseWithClaims(
		tokenStr,
		&AccessClaims{},
		func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, ErrSigningMethod
			}
			return m.config.JWTKey, nil
		},
		jwt.WithIssuer(m.config.Issuer),
		jwt.WithAudience(m.config.Audience),
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (m *Manager) GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}
