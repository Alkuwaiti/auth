package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/mail"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
)

func (s *Service) VerifyEmail(ctx context.Context, rawToken string) error {
	hashedToken := s.TokenManager.Hash(rawToken)

	if err := s.Repo.WithTx(ctx, func(r Repo) error {
		userID, err := r.ConsumeEmailVerificationToken(ctx, hashedToken)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrInvalidEmailVerificationToken
			}
			slog.ErrorContext(ctx, "failed to consume email verification token", "err", err)
			return err
		}

		email, err := r.VerifyUserEmail(ctx, userID)
		if err != nil {
			slog.ErrorContext(ctx, "failed to verify user email", "err", err)
			return err
		}

		meta := contextkeys.RequestMetaFromContext(ctx)

		if err = r.CreateAuditLog(ctx, domain.CreateAuditLogInput{
			UserID:    &userID,
			Action:    domain.ActionVerifyEmail,
			IPAddress: &meta.IPAddress,
			UserAgent: &meta.UserAgent,
		}); err != nil {
			slog.ErrorContext(ctx, "failed to create audit log", "err", err)
			return err
		}

		event := userVerifiedEmail{
			UserID: userID,
			Email:  email,
		}

		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}

		if err = r.CreateOutboxEvent(ctx, domain.OutboxEvent{
			AggregateType: "user",
			AggregateID:   userID.String(),
			EventType:     "user.verified",
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

	return nil
}

func (s *Service) CreateEmailVerificationToken(ctx context.Context, email string) error {
	user, err := s.Repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// don't reveal user
			return nil
		}
		slog.ErrorContext(ctx, "failed to get user by email", "err", err)
		return err
	}

	// user already verified
	if user.IsEmailVerified {
		return nil
	}

	raw, hash, err := s.TokenManager.GenerateToken()
	if err != nil {
		return err
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		if err = r.CreateEmailVerificationToken(ctx, user.ID, hash, time.Now().Add(30*time.Minute)); err != nil {
			slog.ErrorContext(ctx, "failed to create email verification token", "err", err)
			return err
		}

		event := userEmailVerificationRequested{
			UserID: user.ID,
			Email:  user.Email,
			Token:  raw,
		}

		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}

		if err = r.CreateOutboxEvent(ctx, domain.OutboxEvent{
			AggregateType: "user",
			AggregateID:   user.ID.String(),
			EventType:     "user.verification.requested",
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

func (s *Service) StartEmailChange(ctx context.Context, newEmail string) error {
	userID, err := contextkeys.UserIDFromContext(ctx)
	if err != nil {
		return err
	}

	email, err := contextkeys.UserEmailFromContext(ctx)
	if err != nil {
		return err
	}

	newEmail = strings.TrimSpace(newEmail)

	if _, err = mail.ParseAddress(newEmail); err != nil {
		return ErrInvalidEmail
	}

	if newEmail == email {
		return ErrEmailUnchanged
	}

	_, err = s.Repo.GetUserByEmail(ctx, newEmail)
	if err == nil {
		return ErrEmailAlreadyInUse
	}
	if !errors.Is(err, domain.ErrNotFound) {
		slog.ErrorContext(ctx, "failed to get user by email", "err", err)
		return err
	}

	raw, hash, err := s.TokenManager.GenerateToken()
	if err != nil {
		return err
	}

	if err = s.Repo.WithTx(ctx, func(r Repo) error {
		if err = r.CreateEmailChangeRequest(ctx, userID, newEmail, hash, time.Now().Add(15*time.Minute)); err != nil {
			slog.ErrorContext(ctx, "failed to create email change request", "err", err)
			return err
		}

		event := userRequestEmailChange{
			NewEmail: newEmail,
			Email:    email,
			Token:    raw,
		}

		payload, marshalErr := json.Marshal(event)
		if marshalErr != nil {
			return marshalErr
		}

		if err = r.CreateOutboxEvent(ctx, domain.OutboxEvent{
			AggregateType: "user",
			AggregateID:   userID.String(),
			EventType:     "user.email.change.request",
			Payload:       payload,
		}); err != nil {
			slog.ErrorContext(ctx, "failed to create outbox event", "err", err)
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func (s *Service) ConfirmEmailChange(ctx context.Context, token string) error {
	hashedToken := s.TokenManager.Hash(token)

	return s.Repo.WithTx(ctx, func(r Repo) error {
		req, err := r.GetEmailChangeRequestByTokenHash(ctx, hashedToken)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return ErrInvalidEmailChangeToken
			}
			slog.ErrorContext(ctx, "failed to get email change request", "err", err)
			return err
		}

		if err := r.UpdateUserEmail(ctx, req.UserID, req.NewEmail); err != nil {
			if errors.Is(err, domain.ErrRecordAlreadyExists) {
				return ErrEmailAlreadyInUse
			}
			slog.ErrorContext(ctx, "failed to update user email", "err", err)
			return err
		}

		if err := r.DeleteEmailChangeRequest(ctx, req.ID); err != nil {
			slog.ErrorContext(ctx, "failed to delete email change request", "err", err)
			return err
		}

		return nil
	})
}
