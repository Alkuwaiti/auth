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
	"github.com/alkuwaiti/auth/internal/observability"
	"github.com/alkuwaiti/auth/internal/user"
	"github.com/golang-jwt/jwt/v5"
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
	JWTKey   []byte
	Issuer   string
	Audience string
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

func (s *service) Login(ctx context.Context, email, password string, meta observability.RequestMeta) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.Login")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.email_hash", core.HashForTelemetry(email)),
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

	if !checkPasswordHash(password, user.PasswordHash) {
		span.SetStatus(codes.Error, "invalid credentials")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsActive {
		span.SetStatus(codes.Error, "user inactive")
		slog.WarnContext(ctx, "failed login attempt", "is_active", user.IsActive)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsEmailVerified {
		span.SetStatus(codes.Error, "email unverified")
		slog.WarnContext(ctx, "failed login attempt", "is_email_verified", user.IsEmailVerified)
		return TokenPair{}, &apperrors.BadRequestError{
			Field: "email",
			Msg:   "email unverified",
		}
	}

	accessToken, err := generateAccessToken(user.ID.String(), user.Email, s.config.JWTKey, s.config.Issuer, s.config.Audience)

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
	if _, err := s.repo.CreateSession(
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

func generateAccessToken(
	userID, email string,
	secret []byte,
	issuer string,
	audience string,
) (string, error) {

	claims := core.AccessClaims{
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
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

func (s *service) RefreshToken(ctx context.Context, refreshToken string, meta observability.RequestMeta) (TokenPair, error) {
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

	if session.CompromisedAt != nil {
		span.SetStatus(codes.Error, "session already compromised")
		slog.WarnContext(ctx, "attempt to use already compromised session",
			"session_id", session.ID,
			"compromised_at", session.CompromisedAt,
		)
		return TokenPair{}, &apperrors.SessionCompromisedError{}
	}

	if session.IsExpired() {
		span.SetStatus(codes.Error, "session expired")
		slog.WarnContext(ctx, "session expired",
			"session_id", session.ID,
			"session_expires_at", session.ExpiresAt,
		)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if session.RevokedAt != nil {
		span.SetStatus(codes.Error, "revoked token reuse detected")
		slog.WarnContext(ctx, "revoked refresh token reused - possible attack",
			"session_id", session.ID,
			"user_id", session.UserID,
			"revoked_at", session.RevokedAt,
			"revocation_reason", session.RevocationReason,
		)

		// Revoke all active sessions
		if err = s.repo.RevokeAllUserSessions(ctx, session.UserID, RevocationSessionCompromised); err != nil {
			span.RecordError(err)
			slog.ErrorContext(ctx, "failed to revoke user sessions on compromise", "err", err)
		}

		// Mark all as compromised
		if err = s.repo.MarkSessionsCompromised(ctx, session.UserID); err != nil {
			span.RecordError(err)
			slog.ErrorContext(ctx, "failed to mark sessions as compromised", "err", err)
		}

		return TokenPair{}, &apperrors.SessionCompromisedError{}
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		return TokenPair{}, err
	}

	if err = s.repo.RotateSession(
		ctx,
		RotateSessionInput{
			oldSessionID:     session.ID,
			userID:           session.UserID,
			expiry:           session.ExpiresAt,
			revocationReason: RevocationSessionRotation,
			refreshToken:     newRefreshToken,
			ipAddress:        meta.IPAddress,
			userAgent:        meta.UserAgent,
		},
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "session rotation failed")
		return TokenPair{}, err
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

	accessToken, err := generateAccessToken(user.ID.String(), user.Email, s.config.JWTKey, s.config.Issuer, s.config.Audience)
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

func (s *service) Logout(ctx context.Context, refreshToken string) error {
	ctx, span := tracer.Start(ctx, "AuthService.Logout")
	defer span.End()

	session, err := s.repo.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		// already logged out / invalid token → success
		return nil
	}

	_ = s.repo.RevokeSession(ctx, session.ID, RevocationLogout)

	return nil
}

func (s *service) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	slog.InfoContext(ctx, "just some context for now")

	return nil
}
