package auth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
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
		return err
	}

	user, err := s.Repo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			_, _ = s.Passwords.Compare(dummyBcryptHash, oldPassword)
			return ErrInvalidCredentials
		}

		slog.ErrorContext(ctx, "failed to get user by id", "err", err)

		return err
	}

	if user.DeletedAt != nil {
		slog.WarnContext(ctx, "failed login attempt", "email", user.Email, "deleted_at", user.DeletedAt)
		// Don't tell the user they're deleted.
		return ErrInvalidCredentials
	}

	match, err := s.Passwords.Compare(user.PasswordHash, oldPassword)
	if err != nil {
		slog.ErrorContext(ctx, "failed to compare passwords", "err", err)
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}

	match, err = s.Passwords.Compare(user.PasswordHash, newPassword)
	if err != nil {
		slog.ErrorContext(ctx, "failed to compare passwords", "err", err)
		return err
	}
	if match {
		span.SetStatus(codes.Error, "old password cannot be new password")
		return ErrPasswordReuse
	}

	newPasswordHash, err := s.Passwords.Hash(newPassword)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "failed to hash new password")
		slog.ErrorContext(ctx, "failed to hash new password", "err", err)
		return err
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		if txErr := r.UpdatePassword(ctx, userID, newPasswordHash); txErr != nil {
			slog.ErrorContext(ctx, "failed to update password", "err", err)
			return txErr
		}

		if txErr := r.RevokeSessions(ctx, userID, domain.RevocationPasswordChange); txErr != nil {
			slog.ErrorContext(ctx, "failed to revoke sessions", "err", err)
			return txErr
		}

		return nil
	}); err != nil {
		slog.ErrorContext(ctx, "error in transaction", "err", err)
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

func (s *Service) ForgetPassword(ctx context.Context, email string) {
	user, err := s.Repo.GetUserByEmail(ctx, email)
	if errors.Is(err, domain.ErrNotFound) {
		slog.DebugContext(ctx, "user does not exist", "err", err)
		return
	}
	if err != nil {
		slog.ErrorContext(ctx, "error getting user by email")
		return
	}

	randomToken, err := s.tokenManager.GenerateSecureToken()
	if err != nil {
		slog.ErrorContext(ctx, "error generating secure token", "err", err)
		return
	}

	hashedToken := s.Hasher.Hash(randomToken)

	if err = s.Repo.DeleteUserPasswordResetTokens(ctx, user.ID); err != nil {
		slog.ErrorContext(ctx, "error deleting user password reset tokens", "err", err)
		return
	}

	if err = s.Repo.CreatePasswordResetToken(ctx, user.ID, hashedToken, time.Now().Add(20*time.Minute)); err != nil {
		slog.ErrorContext(ctx, "error inserting password reset token", "err", err)
		return
	}

	// TODO: remove, logging for dev
	slog.InfoContext(ctx, "forget password function returned", "randomToken", randomToken)
}

// TODO: finish this later on
// func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
// 	hashedToken := s.Hasher.Hash(token)
//
// 	userID, err := s.Repo.ConsumePasswordResetToken(ctx, hashedToken)
// 	if err != nil {
// 		return err
// 	}
//
// 	return nil
// }
