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
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/core"
	"github.com/alkuwaiti/auth/internal/observability"
	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type service struct {
	repo            *repo
	config          Config
	passwordService passwordService
	auditService    auditService
	flags           featureFlags
}

type Config struct {
	JWTKey   []byte
	Issuer   string
	Audience string
}

func NewService(repo *repo, passwordService passwordService, auditService auditService, flags featureFlags, config Config) *service {
	return &service{
		repo:            repo,
		config:          config,
		passwordService: passwordService,
		auditService:    auditService,
		flags:           flags,
	}
}

type auditService interface {
	CreateAuditLog(ctx context.Context, input audit.CreateAuditLogInput) error
}

type passwordService interface {
	Validate(password string) error
	Hash(password string) (string, error)
	Compare(hash string, password string) error
}

type featureFlags interface {
	RefreshTokensEnabled(ctx context.Context) bool
}

var tracer = otel.Tracer("auth-service/auth")

func (s *service) RegisterUser(ctx context.Context, input RegisterUserInput) (User, error) {
	ctx, span := tracer.Start(ctx, "AuthService.RegisterUser")
	defer span.End()

	meta := observability.RequestMetaFromContext(ctx)

	span.SetAttributes(
		attribute.String("user.username", input.Username),
		attribute.String("user.email_hash", core.HashForTelemetry(input.Email)),
	)

	if err := input.validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "validation failed")
		return User{}, err
	}

	exists, err := s.repo.userExists(ctx, input.Username, input.Email)
	if err != nil {
		slog.WarnContext(ctx, "failed to check if user exists", "email", input.Email, "username", input.Username)
		return User{}, &apperrors.InternalError{
			Msg: "failed to check username or email uniqueness",
			Err: err,
		}
	}
	if exists {
		span.SetStatus(codes.Error, "user already exists")
		return User{}, &apperrors.BadRequestError{
			Field: "user",
			Msg:   "user already exists",
		}
	}

	if err = s.passwordService.Validate(input.Password); err != nil {
		return User{}, err
	}

	newPasswordHash, err := s.passwordService.Hash(input.Password)
	if err != nil {
		return User{}, err
	}

	user, err := s.repo.createUser(ctx, input.Username, input.Email, newPasswordHash)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to register a user",
			Err: err,
		}
	}

	if err = s.auditService.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &user.ID,
		Action:    audit.ActionCreateUser,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.WarnContext(ctx, "failed to create audit log", "err", err)
		return User{}, err
	}

	span.SetAttributes(
		attribute.String("user.id", user.ID.String()),
	)

	span.SetStatus(codes.Ok, "user registered")
	return user, nil
}

func (s *service) Login(ctx context.Context, email, password string) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.Login")
	defer span.End()

	if !s.flags.RefreshTokensEnabled(ctx) {
		span.SetStatus(codes.Error, "Refresh tokens disabled")
		return TokenPair{}, &apperrors.RefreshDisabledError{}
	}

	meta := observability.RequestMetaFromContext(ctx)

	span.SetAttributes(
		attribute.String("user.email_hash", core.HashForTelemetry(email)),
	)

	// TODO: index email in the db.
	user, err := s.repo.getUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Return an invalid credentials here as this is a login endpoint.
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "email", user.Email, "err", err)
		return TokenPair{}, err
	}

	if err = s.passwordService.Compare(user.PasswordHash, password); err != nil {
		span.SetStatus(codes.Error, "invalid credentials")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if user.DeletedAt != nil {
		span.SetStatus(codes.Error, "user deleted")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsActive {
		span.SetStatus(codes.Error, "user inactive")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "is_active", user.IsActive)
		// Don't tell the user they're inactive.
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	accessToken, err := generateAccessToken(s.config.JWTKey, user.Roles, user.ID.String(), user.Email, s.config.Issuer, s.config.Audience)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "access token generation failed")
		slog.ErrorContext(ctx, "access token generation failed", "err", err)
		return TokenPair{}, err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		slog.ErrorContext(ctx, "refresh token generation failed", "err", err)
		return TokenPair{}, err
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if _, err = s.repo.createSession(
		ctx,
		user.ID,
		expiresAt,
		refreshToken,
		meta.IPAddress,
		meta.UserAgent,
	); err != nil {
		slog.ErrorContext(ctx, "create session failed", "err", err)
		return TokenPair{}, err
	}

	if err = s.auditService.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &user.ID,
		Action:    audit.ActionLogin,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
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

// TODO: change the audience when the time comes.
func generateAccessToken(
	secret []byte,
	roles []string,
	userID, email, issuer, audience string,
) (string, error) {

	claims := core.AccessClaims{
		Email: email,
		Roles: roles,
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

	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *service) RefreshToken(ctx context.Context, refreshToken string) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.RefreshToken")
	defer span.End()

	if !s.flags.RefreshTokensEnabled(ctx) {
		span.SetStatus(codes.Error, "Refresh tokens disabled")
		return TokenPair{}, &apperrors.RefreshDisabledError{}
	}

	meta := observability.RequestMetaFromContext(ctx)

	session, err := s.repo.getSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "failed to get session by refresh token", "err", err)
		return TokenPair{}, err
	}

	if session.CompromisedAt != nil {
		span.SetStatus(codes.Error, "session already compromised")
		slog.WarnContext(ctx, "attempt to use already compromised session",
			"session_id", session.ID,
			"compromised_at", session.CompromisedAt,
		)
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
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

		if err = s.repo.revokeAndMarkSessionsCompromised(ctx, session.UserID, RevocationSessionCompromised); err != nil {
			slog.ErrorContext(ctx, "failed to mark sessions as compromised", "err", err)
		}

		if err = s.auditService.CreateAuditLog(ctx, audit.CreateAuditLogInput{
			UserID:    &session.UserID,
			Action:    audit.ActionSessionCompromised,
			IPAddress: &meta.IPAddress,
			UserAgent: &meta.UserAgent,
		}); err != nil {
			slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		}

		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	user, err := s.repo.getUserByID(ctx, session.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "err", err)

		if errors.Is(err, ErrUserNotFound) {
			return TokenPair{}, &apperrors.InvalidCredentialsError{}
		}
		return TokenPair{}, err
	}

	if user.DeletedAt != nil {
		span.SetStatus(codes.Error, "user deleted")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		slog.ErrorContext(ctx, "refresh token generation failed", "err", err)
		return TokenPair{}, err
	}

	if err = s.repo.rotateSession(
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
		slog.ErrorContext(ctx, "session rotation failed", "err", err)
		return TokenPair{}, err
	}

	accessToken, err := generateAccessToken(s.config.JWTKey, user.Roles, user.ID.String(), user.Email, s.config.Issuer, s.config.Audience)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "access token generation failed")
		slog.ErrorContext(ctx, "access token generation failed", "err", err)
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

	meta := observability.RequestMetaFromContext(ctx)

	session, err := s.repo.getSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		// already logged out / invalid token → success
		slog.ErrorContext(ctx, "failed to get session by refresh token", "err", err)
		return nil
	}

	if err = s.repo.revokeSession(ctx, session.ID, RevocationLogout); err != nil {
		slog.ErrorContext(ctx, "failed to revoke session", "err", err)
	}

	if err = s.auditService.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &session.UserID,
		Action:    audit.ActionLogout,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
	}

	span.SetStatus(codes.Ok, "user logged out")

	return nil
}

var dummyBcryptHash = "$2b$12$C6UzMDM.H6dfI/f/IKcEeOe2x7yZ0pniS3pSDOMkMt2rt7V6F2i4G"

// This is the authenticated flow.
// TODO: check if user is admin.
func (s *service) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	ctx, span := tracer.Start(ctx, "AuthService.ChangePassword")
	defer span.End()

	userID, err := core.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	meta := observability.RequestMetaFromContext(ctx)

	if err = s.passwordService.Validate(newPassword); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to validate password")
		return err
	}

	user, err := s.repo.getUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			_ = s.passwordService.Compare(dummyBcryptHash, oldPassword)
			return &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "failed to get user by id", "err", err)

		return err
	}

	if user.DeletedAt != nil {
		span.SetStatus(codes.Error, "user deleted")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return &apperrors.InvalidCredentialsError{}
	}

	if err = s.passwordService.Compare(
		user.PasswordHash,
		oldPassword,
	); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "old password and current password do not match")
		return &apperrors.InvalidCredentialsError{}
	}

	if err = s.passwordService.Compare(
		user.PasswordHash,
		newPassword,
	); err == nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "old password cannot be new password")
		return &apperrors.PasswordReuseError{}
	}

	newPasswordHash, err := s.passwordService.Hash(newPassword)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to hash new password")
		slog.ErrorContext(ctx, "failed to hash new password", "err", err)
		return err
	}

	if err = s.repo.updatePasswordAndRevokeSessions(
		ctx,
		userID,
		newPasswordHash,
		RevocationPasswordChange,
	); err != nil {
		slog.ErrorContext(ctx, "failed to update password and revoke sessions", "err", err)
		return err
	}

	if err = s.auditService.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &user.ID,
		Action:    audit.ActionPasswordChange,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
	}

	span.SetAttributes(
		attribute.String("user.email_hash", core.HashForTelemetry(user.Email)),
	)
	span.SetStatus(codes.Ok, "password changed")

	return nil
}

// TODO: only allow specific roles to use this method.
func (s *service) DeleteUser(ctx context.Context, input DeleteUserInput) error {
	ctx, span := tracer.Start(ctx, "AuthService.DeleteUser")
	defer span.End()

	if err := input.validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to validate deletion reason")
		slog.ErrorContext(ctx, "failed to validate deletion reason", "err", err)
		return err
	}

	meta := observability.RequestMetaFromContext(ctx)

	if err := s.repo.deleteUserAndRevokeSessions(ctx, input.UserID, input.DeletionReason, RevocationUserDeleted); err != nil {
		if errors.Is(err, ErrUserNotFoundOrAlreadyDeleted) {
			return &apperrors.BadRequestError{
				Field: "user uuid",
				Msg:   "User not found or already deleted",
			}
		}
		slog.ErrorContext(ctx, "failed to delete user and revoke sessions", "err", err)
		return err
	}

	if err := s.auditService.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &input.UserID,
		ActorID:   &input.ActorID,
		Action:    audit.ActionDeleteUser,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
		Context: audit.AuditContext{
			"deletion": map[string]any{
				"reason": string(input.DeletionReason),
				"note":   input.Note,
			},
		},
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		return err
	}

	span.SetStatus(codes.Ok, "user deleted and sessions revoked")

	return nil
}
