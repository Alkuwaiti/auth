package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/alkuwaiti/auth/internal/audit"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

var dummyBcryptHash = "$2b$12$C6UzMDM.H6dfI/f/IKcEeOe2x7yZ0pniS3pSDOMkMt2rt7V6F2i4G"

// TODO: check the impact of nullifying the password hash with the introduction of social login.

func (s *Service) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	ctx, span := tracer.Start(ctx, "AuthService.ChangePassword")
	defer span.End()

	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	email, err := contextkeys.UserEmailFromContext(ctx)
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

	// social login users have nil password hashes, so this is necessary.
	if user.PasswordHash != nil {
		var match bool
		match, err = s.Passwords.Compare(*user.PasswordHash, oldPassword)
		if err != nil {
			slog.ErrorContext(ctx, "failed to compare passwords", "err", err)
			return err
		}
		if !match {
			return ErrInvalidCredentials
		}

		match, err = s.Passwords.Compare(*user.PasswordHash, newPassword)
		if err != nil {
			slog.ErrorContext(ctx, "failed to compare passwords", "err", err)
			return err
		}
		if match {
			return ErrPasswordReuse
		}
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

		event := userChangePassword{
			Email:     email,
			ChangedAt: time.Now(),
		}

		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}

		if err = r.CreateOutboxEvent(ctx, domain.OutboxEvent{
			AggregateType: "user",
			AggregateID:   user.ID.String(),
			EventType:     "user.change.password",
			Payload:       payload,
		}); err != nil {
			slog.ErrorContext(ctx, "error creating outbox event", "err", err)
			return err
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

func (s *Service) ForgetPassword(ctx context.Context, email string) error {
	user, err := s.Repo.GetUserByEmail(ctx, email)
	if errors.Is(err, domain.ErrNotFound) {
		// artificial delay
		time.Sleep(150 * time.Millisecond)
		slog.DebugContext(ctx, "user does not exist", "err", err)
		return nil
	}
	if err != nil {
		slog.ErrorContext(ctx, "error getting user by email")
		return nil
	}

	rawToken, hashedToken, err := s.TokenManager.GenerateToken()
	if err != nil {
		slog.ErrorContext(ctx, "error generating secure token", "err", err)
		return nil
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		if err = r.CreatePasswordResetToken(ctx, user.ID, hashedToken, time.Now().Add(20*time.Minute)); err != nil {
			slog.ErrorContext(ctx, "error inserting password reset token", "err", err)
			return nil
		}

		event := userForgetPassword{
			Email: email,
			Token: rawToken,
		}

		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}

		if err = r.CreateOutboxEvent(ctx, domain.OutboxEvent{
			AggregateType: "user",
			AggregateID:   user.ID.String(),
			EventType:     "user.forget.password",
			Payload:       payload,
		}); err != nil {
			slog.ErrorContext(ctx, "error creating outbox event", "err", err)
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// TODO: add tests

func (s *Service) ResetPassword(ctx context.Context, token, newPassword string) error {
	var (
		userID uuid.UUID
		email  string
		err    error
	)
	hashedToken := s.TokenManager.Hash(token)

	if err = s.Passwords.Validate(newPassword); err != nil {
		return err
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		userID, email, err = r.ConsumePasswordResetToken(ctx, hashedToken)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrInvalidResetToken
			}
			return err
		}

		var hashedPassword string
		hashedPassword, err = s.Passwords.Hash(newPassword)
		if err != nil {
			return err
		}

		if err = r.UpdatePassword(ctx, userID, hashedPassword); err != nil {
			return err
		}

		if err = r.RevokeSessions(ctx, userID, domain.RevocationPasswordChange); err != nil {
			return err
		}

		event := userChangePassword{
			Email:     email,
			ChangedAt: time.Now(),
		}

		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}

		if err = r.CreateOutboxEvent(ctx, domain.OutboxEvent{
			AggregateType: "user",
			AggregateID:   userID.String(),
			EventType:     "user.reset.password",
			Payload:       payload,
		}); err != nil {
			slog.ErrorContext(ctx, "error creating outbox event", "err", err)
			return err
		}

		return nil

	}); err != nil {
		return err
	}

	meta := contextkeys.RequestMetaFromContext(ctx)

	if err := s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
		UserID:    &userID,
		Action:    audit.ActionPasswordReset,
		IPAddress: &meta.IPAddress,
		UserAgent: &meta.UserAgent,
	}); err != nil {
		slog.ErrorContext(ctx, "failed to create audit log", "err", err)
		return err
	}

	return nil
}
