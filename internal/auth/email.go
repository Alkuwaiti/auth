package auth

import (
	"context"
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

		if err = r.VerifyUserEmail(ctx, userID); err != nil {
			slog.ErrorContext(ctx, "failed to verify user email", "err", err)
			return err
		}

		meta := contextkeys.RequestMetaFromContext(ctx)

		if err := s.auditor.CreateAuditLog(ctx, audit.CreateAuditLogInput{
			UserID:    &userID,
			Action:    audit.ActionVerifyEmail,
			IPAddress: &meta.IPAddress,
			UserAgent: &meta.UserAgent,
		}); err != nil {
			slog.ErrorContext(ctx, "failed to create audit log", "err", err)
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

func (s *Service) ResendEmailVerification(ctx context.Context, email string) error {
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

		if err = r.CreateEmailVerificationToken(
			ctx,
			user.ID,
			hash,
			time.Now().Add(24*time.Hour),
		); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	// TODO: remove this. for dev only.
	slog.DebugContext(ctx, "this is the raw verification token", "raw_token", raw)

	return nil
}
