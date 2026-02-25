package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type tokens struct {
	config Config
}

func New(cfg Config) *tokens {
	return &tokens{
		config: cfg,
	}
}

func (m *tokens) Compare(hashedInput, input string) bool {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:]) == hashedInput
}

func (m *tokens) Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

func (m *tokens) GenerateAccessToken(roles []string, userID, email string) (string, error) {
	claims := AccessClaims{
		Email: email,
		Roles: roles,
		Type:  string(AccessToken),
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

func (m *tokens) ValidateJWT(tokenStr string) (*AccessClaims, error) {
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

	if claims.Type != string(AccessToken) {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}

func (m *tokens) GenerateToken() (raw string, hash string, err error) {
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		return "", "", err
	}

	raw = base64.URLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(h[:])

	return
}

func (m *tokens) GenerateStepUpToken(userID, email, scope string) (string, int, error) {
	expiresAt := time.Now().Add(5 * time.Minute)
	claims := StepUpClaims{
		Email: email,
		Scope: scope,
		Type:  string(StepUpToken),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    m.config.Issuer,
			Audience:  jwt.ClaimStrings{m.config.Audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(m.config.JWTKey)
	return tokenString, int(expiresAt.Unix()), err
}

func (m *tokens) ValidateStepUpToken(tokenStr string) (*StepUpClaims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&StepUpClaims{},
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

	claims, ok := token.Claims.(*StepUpClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Type != string(StepUpToken) {
		return nil, ErrInvalidTokenType
	}

	return claims, nil
}
