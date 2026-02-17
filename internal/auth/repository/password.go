package repository

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return r.queries.CreatePasswordResetToken(ctx, postgres.CreatePasswordResetTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
}

func (r *repo) DeleteUserPasswordResetTokens(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DeleteUserPasswordResetTokens(ctx, userID)
}

func (r *repo) PasswordResetTokenExists(ctx context.Context, tokenHash string) (bool, error) {
	exists, err := r.queries.PasswordResetTokenExists(ctx, tokenHash)
	if err != nil {
		return false, err
	}

	return exists, nil
}
