// Package auth handles tokens business logic
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/core"
	"github.com/alkuwaiti/auth/internal/user"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/crypto/bcrypt"
)

type service struct {
	repo        *repo
	userService userService
	config      Config
}

type Config struct {
	JWTKey []byte
}

func NewService(repo *repo, userService userService, config Config) *service {
	return &service{
		repo:        repo,
		userService: userService,
		config:      config,
	}
}

type userService interface {
	GetUserByEmail(ctx context.Context, email string) (user.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (user.User, error)
}

var tracer = otel.Tracer("auth-service/auth")

func (s *service) Login(ctx context.Context, email, password string, meta core.RequestMeta) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.Login")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.email_hash", hashForTelemetry(email)),
	)

	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "user lookup failed")

		if errors.Is(err, core.ErrUserNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "err", err)
		return TokenPair{}, err
	}

	_, pwdSpan := tracer.Start(ctx, "AuthService.VerifyPassword")
	ok := checkPasswordHash(password, user.PasswordHash)
	pwdSpan.End()

	if !ok {
		span.SetStatus(codes.Error, "invalid credentials")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsActive {
		span.SetStatus(codes.Error, "user inactive")
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsEmailVerified {
		span.SetStatus(codes.Error, "email unverified")
		return TokenPair{}, &apperrors.BadRequestError{
			Field: "email",
			Msg:   "email unverified",
		}
	}

	_, tokenSpan := tracer.Start(ctx, "AuthService.GenerateAccessToken")
	accessToken, err := generateAccessToken(user.ID.String(), user.Email, s.config.JWTKey)
	tokenSpan.End()

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "access token generation failed")
		return TokenPair{}, err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		return TokenPair{}, err
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if err := s.repo.CreateSession(
		ctx,
		user.ID,
		expiresAt,
		refreshToken,
		meta.IPAddress,
		meta.UserAgent,
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "session creation failed")
		return TokenPair{}, err
	}

	span.SetAttributes(
		attribute.String("user.id", user.ID.String()),
	)

	span.SetStatus(codes.Ok, "login successful")

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

func generateAccessToken(userID, email string, secret []byte) (string, error) {
	claims := jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	token := base64.URLEncoding.EncodeToString(b)

	return token, nil
}

func (s *service) RefreshToken(ctx context.Context, refreshToken string, meta core.RequestMeta) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.RefreshToken")
	defer span.End()

	session, err := s.repo.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "session lookup failed")

		if errors.Is(err, core.ErrSessionNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}
		return TokenPair{}, err
	}

	if !session.RevokedAt.IsZero() {
		span.SetStatus(codes.Error, "refresh token reuse detected")
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if session.ExpiresAt.Before(time.Now()) {
		span.SetStatus(codes.Error, "session expired")
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	user, err := s.userService.GetUserByID(ctx, session.UserID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "user lookup failed")

		if errors.Is(err, core.ErrUserNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}
		return TokenPair{}, err
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		return TokenPair{}, err
	}

	if err = s.repo.RotateSession(
		ctx,
		session.ID,
		user.ID,
		session.ExpiresAt,
		newRefreshToken,
		meta.IPAddress,
		meta.UserAgent,
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "session rotation failed")
		return TokenPair{}, err
	}

	accessToken, err := generateAccessToken(user.ID.String(), user.Email, s.config.JWTKey)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "access token generation failed")
		return TokenPair{}, err
	}

	span.SetAttributes(
		attribute.String("user.id", user.ID.String()),
	)
	span.SetStatus(codes.Ok, "token refreshed")

	return TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     newRefreshToken,
		RefreshExpiresAt: session.ExpiresAt,
		UserID:           user.ID,
	}, nil
}

func hashForTelemetry(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}
