package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/passwords"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type LoginResult struct {
	RequiresMFA bool
	ChallengeID *uuid.UUID
	Tokens      *TokenPair
}

func (s *Service) Login(ctx context.Context, email string, password string, rememberMe bool) (LoginResult, error) {
	if !s.Flags.RefreshTokensEnabled(ctx) {
		return LoginResult{}, ErrRefreshDisabled
	}

	user, err := s.Repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// Return an invalid credentials here as this is a login endpoint.
			return LoginResult{}, ErrInvalidCredentials
		}

		slog.ErrorContext(ctx, "login failed: user lookup error", "email", user.Email, "err", err)
		return LoginResult{}, err
	}

	match, err := passwords.Compare(*user.PasswordHash, password)
	if err != nil {
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email)
		return LoginResult{}, err
	}
	if !match {
		return LoginResult{}, ErrInvalidCredentials
	}

	if user.DeletedAt != nil {
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return LoginResult{}, ErrInvalidCredentials
	}

	if !user.IsActive {
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "is_active", user.IsActive)
		// Don't tell the user they're inactive.
		return LoginResult{}, ErrInvalidCredentials
	}

	methods, err := s.Repo.GetMFAMethodsConfirmedByUser(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get confirmed mfa methods by user", "err", err)
		return LoginResult{}, err
	}

	var challenge domain.MFAChallenge
	if len(methods) > 0 {
		challenge, err = s.Repo.CreateChallenge(ctx, domain.MFAChallenge{
			MethodID:      methods[0].ID,
			UserID:        user.ID,
			Scope:         domain.ScopeLogin,
			ChallengeType: domain.ChallengeLogin,
			RememberMe:    rememberMe,
			ExpiresAt:     time.Now().Add(5 * time.Minute),
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

	tokenPair, err := s.finalizeLogin(ctx, user, domain.ActionLogin, rememberMe)
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		RequiresMFA: false,
		ChallengeID: nil,
		Tokens:      &tokenPair,
	}, nil
}

func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.RefreshToken")
	defer span.End()

	if !s.Flags.RefreshTokensEnabled(ctx) {
		return TokenPair{}, ErrRefreshDisabled
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	hashedToken := s.TokenManager.Hash(refreshToken)
	session, err := s.Repo.GetSessionByRefreshToken(ctx, hashedToken)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return TokenPair{}, ErrInvalidCredentials
		}

		slog.ErrorContext(ctx, "failed to get session by refresh token", "err", err)
		return TokenPair{}, err
	}

	if session.CompromisedAt != nil {
		slog.WarnContext(ctx, "attempt to use already compromised session",
			"session_id", session.ID,
			"compromised_at", session.CompromisedAt,
			"user_id", session.UserID,
		)
		return TokenPair{}, ErrInvalidCredentials
	}

	if session.IsExpired() {
		slog.WarnContext(ctx, "session expired",
			"session_id", session.ID,
			"session_expires_at", session.ExpiresAt,
		)
		return TokenPair{}, ErrInvalidCredentials
	}

	if session.RevokedAt != nil {
		slog.WarnContext(ctx, "revoked refresh token reused - possible attack",
			"session_id", session.ID,
			"user_id", session.UserID,
			"revoked_at", session.RevokedAt,
			"revocation_reason", session.RevocationReason,
		)

		if err = s.Repo.WithTx(ctx, func(r Repo) error {
			if err = r.RevokeSessions(ctx, session.UserID, domain.RevocationSessionCompromised); err != nil {
				slog.ErrorContext(ctx, "failed to revoke sessions", "err", err)
				return err
			}

			if err = r.MarkSessionsCompromised(ctx, session.UserID); err != nil {
				slog.ErrorContext(ctx, "failed to mark sessions as compromised", "err", err)
				return err
			}

			if err = r.CreateAuditLog(ctx, domain.CreateAuditLogInput{
				UserID:    &session.UserID,
				Action:    domain.ActionSessionCompromised,
				IPAddress: &meta.IPAddress,
				UserAgent: &meta.UserAgent,
			}); err != nil {
				slog.ErrorContext(ctx, "failed to create audit log", "err", err)
			}

			return nil
		}); err != nil {
			slog.ErrorContext(ctx, "error in transaction", "err", err)
			return TokenPair{}, err
		}

		return TokenPair{}, ErrInvalidCredentials
	}

	user, err := s.Repo.GetUserByID(ctx, session.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "failed to get user by id", "err", err)

		if errors.Is(err, domain.ErrNotFound) {
			return TokenPair{}, ErrInvalidCredentials
		}
		return TokenPair{}, err
	}

	if user.DeletedAt != nil {
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return TokenPair{}, ErrInvalidCredentials
	}

	rawToken, hashedToken, err := s.TokenManager.GenerateToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		slog.ErrorContext(ctx, "refresh token generation failed", "err", err)
		return TokenPair{}, err
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		if err = r.RevokeSession(ctx, session.ID, domain.RevocationSessionRotation); err != nil {
			slog.ErrorContext(ctx, "session revocation failed", "err", err)
			return err
		}

		if _, err = r.CreateSession(ctx, user.ID, session.ExpiresAt, hashedToken, meta.IPAddress, meta.UserAgent); err != nil {
			slog.ErrorContext(ctx, "creating session failed", "err", err)
			return err
		}

		return nil
	}); err != nil {
		slog.ErrorContext(ctx, "transaction error", "err", err)
		return TokenPair{}, err
	}

	accessToken, err := s.TokenManager.GenerateAccessToken(user.Roles, user.ID.String(), user.Email)
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
		RefreshToken:     rawToken,
		RefreshExpiresAt: session.ExpiresAt,
		UserID:           user.ID,
	}, nil
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	ctx, span := tracer.Start(ctx, "AuthService.Logout")
	defer span.End()

	meta := contextkeys.RequestMetaFromContext(ctx)

	hashedToken := s.TokenManager.Hash(refreshToken)
	session, err := s.Repo.GetSessionByRefreshToken(ctx, hashedToken)
	if err != nil {
		// already logged out / invalid token → success
		slog.ErrorContext(ctx, "failed to get session by refresh token", "err", err)
		return nil
	}

	if err = s.Repo.RevokeSession(ctx, session.ID, domain.RevocationLogout); err != nil {
		slog.ErrorContext(ctx, "failed to revoke session", "err", err)
	}

	if err = s.Repo.CreateAuditLog(ctx, domain.CreateAuditLogInput{
		UserID:    &session.UserID,
		Action:    domain.ActionLogout,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
	}

	span.SetStatus(codes.Ok, "user logged out")

	return nil
}

func (s *Service) finalizeLogin(ctx context.Context, user domain.User, action domain.AuditAction, rememberMe bool) (TokenPair, error) {
	ctx, span := tracer.Start(ctx, "AuthService.finalizeLogin")
	defer span.End()

	accessToken, err := s.TokenManager.GenerateAccessToken(user.Roles, user.ID.String(), user.Email)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "access token generation failed")
		slog.ErrorContext(ctx, "access token generation failed", "err", err)
		return TokenPair{}, err
	}

	rawToken, hashedToken, err := s.TokenManager.GenerateToken()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "refresh token generation failed")
		slog.ErrorContext(ctx, "refresh token generation failed", "err", err)
		return TokenPair{}, err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	var expiresAt time.Time
	if rememberMe {
		expiresAt = time.Now().Add(30 * 24 * time.Hour)
	} else {
		expiresAt = time.Now().Add(7 * 24 * time.Hour)
	}

	if _, err = s.Repo.CreateSession(
		ctx,
		user.ID,
		expiresAt,
		hashedToken,
		meta.IPAddress,
		meta.UserAgent,
	); err != nil {
		slog.ErrorContext(ctx, "create session failed", "err", err)
		return TokenPair{}, err
	}

	if err = s.Repo.CreateAuditLog(ctx, domain.CreateAuditLogInput{
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
		RefreshToken:     rawToken,
		RefreshExpiresAt: expiresAt,
		UserID:           user.ID,
	}, nil
}
