package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/auth/repository"
	"github.com/alkuwaiti/auth/internal/contextkeys"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type LoginResult struct {
	RequiresMFA bool
	ChallengeID *uuid.UUID
	Tokens      *TokenPair
}

func (s *service) Login(ctx context.Context, email, password string) (LoginResult, error) {
	ctx, span := tracer.Start(ctx, "AuthService.Login")
	defer span.End()

	if !s.flags.RefreshTokensEnabled(ctx) {
		span.SetStatus(codes.Error, "Refresh tokenManager disabled")
		return LoginResult{}, &apperrors.RefreshDisabledError{}
	}

	span.SetAttributes(
		attribute.String("user.email", email),
	)

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Return an invalid credentials here as this is a login endpoint.
			return LoginResult{}, &apperrors.InvalidCredentialsError{}
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "email", user.Email, "err", err)
		return LoginResult{}, err
	}

	match, err := s.passwords.Compare(user.PasswordHash, password)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "invalid credentials")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email)
		return LoginResult{}, err
	}
	if !match {
		return LoginResult{}, &apperrors.InvalidCredentialsError{}
	}

	if user.DeletedAt != nil {
		span.SetStatus(codes.Error, "user deleted")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return LoginResult{}, &apperrors.InvalidCredentialsError{}
	}

	if !user.IsActive {
		span.SetStatus(codes.Error, "user inactive")
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "is_active", user.IsActive)
		// Don't tell the user they're inactive.
		return LoginResult{}, &apperrors.InvalidCredentialsError{}
	}

	methods, err := s.repo.GetMFAMethodsConfirmedByUser(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get confirmed mfa methods by user", "err", err)
		return LoginResult{}, err
	}

	var challenge domain.MFAChallenge
	if len(methods) > 0 {
		// TODO: change the implementation when you have multiple methods.
		challenge, err = s.repo.CreateChallenge(ctx, domain.MFAChallenge{
			MethodID:      methods[0].ID,
			UserID:        user.ID,
			Scope:         domain.ScopeLogin,
			ChallengeType: domain.ChallengeLogin,
		})
		if err != nil {
			return LoginResult{}, err
		}

		return LoginResult{
			RequiresMFA: true,
			ChallengeID: &challenge.ID,
			Tokens:      nil,
		}, nil
	}

	tokenPair, err := s.finalizeLogin(ctx, user, audit.ActionLogin)
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		RequiresMFA: false,
		ChallengeID: nil,
		Tokens:      &tokenPair,
	}, nil
}

func (s *service) RefreshToken(ctx context.Context, refreshToken string) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.RefreshToken")
	defer span.End()

	if !s.flags.RefreshTokensEnabled(ctx) {
		span.SetStatus(codes.Error, "Refresh tokenManager disabled")
		return TokenPair{}, &apperrors.RefreshDisabledError{}
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	session, err := s.repo.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
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

		if err = s.repo.RevokeAndMarkSessionsCompromised(ctx, session.UserID, domain.RevocationSessionCompromised); err != nil {
			slog.ErrorContext(ctx, "failed to mark sessions as compromised", "err", err)
		}

		if err = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
			UserID:    &session.UserID,
			Action:    audit.ActionSessionCompromised,
			IPAddress: &meta.IPAddress,
			UserAgent: &meta.UserAgent,
		}); err != nil {
			slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		}

		return TokenPair{}, &apperrors.InvalidCredentialsError{}
	}

	user, err := s.repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "err", err)

		if errors.Is(err, repository.ErrNotFound) {
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

	newRefreshToken, err := s.tokenManager.GenerateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		slog.ErrorContext(ctx, "refresh token generation failed", "err", err)
		return TokenPair{}, err
	}

	if err = s.repo.RotateSession(
		ctx,
		domain.RotateSessionInput{
			OldSessionID:     session.ID,
			UserID:           session.UserID,
			Expiry:           session.ExpiresAt,
			RevocationReason: domain.RevocationSessionRotation,
			RefreshToken:     newRefreshToken,
			IPAddress:        meta.IPAddress,
			UserAgent:        meta.UserAgent,
		},
	); err != nil {
		slog.ErrorContext(ctx, "session rotation failed", "err", err)
		return TokenPair{}, err
	}

	accessToken, err := s.tokenManager.GenerateAccessToken(user.Roles, user.ID.String(), user.Email)
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

	meta := contextkeys.RequestMetaFromContext(ctx)

	session, err := s.repo.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		// already logged out / invalid token → success
		slog.ErrorContext(ctx, "failed to get session by refresh token", "err", err)
		return nil
	}

	if err = s.repo.RevokeSession(ctx, session.ID, domain.RevocationLogout); err != nil {
		slog.ErrorContext(ctx, "failed to revoke session", "err", err)
	}

	if err = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
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

func (s *service) finalizeLogin(ctx context.Context, user domain.User, action audit.AuditAction) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.finalizeLogin")
	defer span.End()

	accessToken, err := s.tokenManager.GenerateAccessToken(user.Roles, user.ID.String(), user.Email)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "access token generation failed")
		slog.ErrorContext(ctx, "access token generation failed", "err", err)
		return TokenPair{}, err
	}

	refreshToken, err := s.tokenManager.GenerateRefreshToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		slog.ErrorContext(ctx, "refresh token generation failed", "err", err)
		return TokenPair{}, err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	if _, err = s.repo.CreateSession(
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

	if err = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &user.ID,
		Action:    action,
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
