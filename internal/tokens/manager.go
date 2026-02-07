package tokens

import (
	"crypto/rand"
	"encoding/base64"
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

func (m *tokens) GenerateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func (m *tokens) GenerateStepUpToken(userID, email, scope string) (string, time.Time, error) {
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
	return tokenString, expiresAt, err
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

func (m *tokens) GenerateBackupCodes(n int, hash func(string) (string, error)) (plain []string, hashed []string, err error) {
	plain = make([]string, 0, n)
	hashed = make([]string, 0, n)

	for range n {
		raw, err := generateBackupCode(8)
		if err != nil {
			return nil, nil, err
		}

		formatted := formatBackupCode(raw)

		hash, err := hash(formatted)
		if err != nil {
			return nil, nil, err
		}

		plain = append(plain, formatted)
		hashed = append(hashed, hash)
	}

	return plain, hashed, nil
}

// no O, I, 0, 1 → avoids confusion
var backupCodeAlphabet = []rune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

func generateBackupCode(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	runes := make([]rune, length)
	for i := range b {
		runes[i] = backupCodeAlphabet[int(b[i])%len(backupCodeAlphabet)]
	}

	return string(runes), nil
}

func formatBackupCode(raw string) string {
	// e.g. ABCDEFGH → ABCD-EFGH
	if len(raw) != 8 {
		return raw
	}
	return raw[:4] + "-" + raw[4:]
}
