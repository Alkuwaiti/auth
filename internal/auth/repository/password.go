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

func (r *Repo) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return r.queries.CreatePasswordResetToken(ctx, postgres.CreatePasswordResetTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
}

func (r *Repo) ConsumePasswordResetToken(ctx context.Context, tokenHash string) (uuid.UUID, error) {
	userID, err := r.queries.ConsumePasswordResetToken(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, domain.ErrNotFound
		}

		return uuid.Nil, err
	}

	return userID, nil
}

func (r *Repo) UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	return r.queries.UpdatePassword(ctx, postgres.UpdatePasswordParams{
		ID: userID,
		PasswordHash: sql.NullString{
			String: newPasswordHash,
			Valid:  newPasswordHash != "",
		},
	})
}
