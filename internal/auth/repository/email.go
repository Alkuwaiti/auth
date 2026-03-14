package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *Repo) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash string, ExpiresAt time.Time) error {
	return r.queries.CreateEmailVerificationToken(ctx, postgres.CreateEmailVerificationTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: ExpiresAt,
	})
}

func (r *Repo) ConsumeEmailVerificationToken(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	userID, err := r.queries.ConsumeEmailVerificationToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, domain.ErrNotFound
		}

		return uuid.Nil, err
	}

	return userID, nil
}

func (r *Repo) VerifyUserEmail(ctx context.Context, userID uuid.UUID) (string, error) {
	return r.queries.VerifyUserEmail(ctx, userID)
}

func (r *Repo) InvalidateEmailVerificationTokens(ctx context.Context, userID uuid.UUID) error {
	return r.queries.InvalidateEmailVerificationTokens(ctx, userID)
}

func (r *Repo) CreateEmailChangeRequest(ctx context.Context, userID uuid.UUID, newEmail string, tokenHash string, ExpiresAt time.Time) error {
	return r.queries.CreateEmailChangeRequest(ctx, postgres.CreateEmailChangeRequestParams{
		UserID:    userID,
		NewEmail:  newEmail,
		TokenHash: tokenHash,
		ExpiresAt: ExpiresAt,
	})
}

func (r *Repo) GetEmailChangeRequestByTokenHash(ctx context.Context, tokenHash string) (domain.ChangeEmailRequest, error) {
	changeEmailRequestRow, err := r.queries.GetEmailChangeRequestByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ChangeEmailRequest{}, domain.ErrNotFound
		}

		return domain.ChangeEmailRequest{}, err
	}

	return domain.ChangeEmailRequest{
		UserID:   changeEmailRequestRow.UserID,
		NewEmail: changeEmailRequestRow.NewEmail,
	}, nil
}

func (r *Repo) UpdateUserEmail(ctx context.Context, userID uuid.UUID, email string) error {
	return r.queries.UpdateUserEmail(ctx, postgres.UpdateUserEmailParams{
		ID:    userID,
		Email: email,
	})
}
