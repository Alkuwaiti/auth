package auth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/auth/repository"
	"github.com/alkuwaiti/auth/internal/contextkeys"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var dummyBcryptHash = "$2b$12$C6UzMDM.H6dfI/f/IKcEeOe2x7yZ0pniS3pSDOMkMt2rt7V6F2i4G"

func (s *Service) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	ctx, span := tracer.Start(ctx, "AuthService.ChangePassword")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	if err = s.Passwords.Validate(newPassword); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to validate password")
		return err
	}

	user, err := s.Repo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			_, _ = s.Passwords.Compare(dummyBcryptHash, oldPassword)
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

	match, err := s.Passwords.Compare(user.PasswordHash, oldPassword)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to compare passwords")
		slog.ErrorContext(ctx, "failed to compare passwords", "err", err)
		return err
	}
	if !match {
		span.SetStatus(codes.Error, "old password and current password do not match")
		return &apperrors.InvalidCredentialsError{}
	}

	match, err = s.Passwords.Compare(user.PasswordHash, newPassword)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to compare passwords")
		slog.ErrorContext(ctx, "failed to compare passwords", "err", err)
		return err
	}
	if match {
		span.SetStatus(codes.Error, "old password cannot be new password")
		return &apperrors.PasswordReuseError{}
	}

	newPasswordHash, err := s.Passwords.Hash(newPassword)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to hash new password")
		slog.ErrorContext(ctx, "failed to hash new password", "err", err)
		return err
	}

	if err = s.Repo.UpdatePasswordAndRevokeSessions(ctx, userID, newPasswordHash, domain.RevocationPasswordChange); err != nil {
		slog.ErrorContext(ctx, "failed to update password and revoke sessions", "err", err)
		return err
	}

	if err = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &user.ID,
		Action:    audit.ActionPasswordChange,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
	}

	span.SetAttributes(
		attribute.String("user.email", user.Email),
	)
	span.SetStatus(codes.Ok, "password changed")

	return nil
}
