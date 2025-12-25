// Package auth handles tokens business logic
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/core"
	userDomain "github.com/alkuwaiti/auth/internal/user"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	repo        *repo
	userService userService
	config      Config
}

type Config struct {
	JWTKey string
}

func NewService(repo *repo, userService userService, config Config) *service {
	return &service{
		repo:        repo,
		userService: userService,
	}
}

type userService interface {
	GetUserByEmail(ctx context.Context, email string) (userDomain.User, error)
}

func (s *service) Login(ctx context.Context, email, password string, meta core.RequestMeta) (TokenPair, error) {

	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "err", err)
		return TokenPair{}, err
	}

	// always check password hash first to cripple timing attacks.
	if !checkPasswordHash(password, user.PasswordHash) {
		slog.ErrorContext(ctx, "failed login attempt", "email", user.Email)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsActive {
		slog.ErrorContext(ctx, "failed login attempt", "is_active", user.IsActive)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsEmailVerified {
		return TokenPair{}, &apperrors.BadRequestError{
			Field: "email",
			Msg:   "email unverified",
		}
	}

	accessToken, err := generateAccessToken(user.ID.String(), []byte(s.config.JWTKey))
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken, hashedRefreshToken, err := generateRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	err = s.repo.CreateSession(ctx, user.ID, expiresAt, hashedRefreshToken, meta.IPAddress, meta.UserAgent)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: expiresAt,
		UserID:           user.ID,
	}, nil

}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateAccessToken(userID string, secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(15 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func generateRefreshToken() (string, string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", "", err
	}
	token := base64.URLEncoding.EncodeToString(b)
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return token, string(hashedToken), nil
}
