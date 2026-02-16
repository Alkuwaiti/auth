package repository

import (
	"context"
	"database/sql"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) CreatePasswordResetToken(ctx context.Context, tx *sql.Tx, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return r.queries.WithTx(tx).CreatePasswordResetToken(ctx, postgres.CreatePasswordResetTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
}

func (r *repo) DeleteUserPasswordResetTokens(ctx context.Context, tx *sql.Tx, userID uuid.UUID) error {
	return r.queries.WithTx(tx).DeleteUserPasswordResetTokens(ctx, userID)
}
