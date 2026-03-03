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
)

// TODO: write tests for this.

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

		if err = s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
			UserID:    &userID,
			Action:    audit.ActionVerifyEmail,
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

// TODO: write tests for this.

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
		if err = r.InvalidateEmailVerificationTokens(ctx, user.ID); err != nil {
			return err
		}

		if err = r.CreateEmailVerificationToken(ctx, user.ID, hash, time.Now().Add(30*time.Minute)); err != nil {
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
