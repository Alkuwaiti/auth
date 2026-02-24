package repository

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash string, ExpiresAt time.Time) error {
	return r.queries.CreateEmailVerificationToken(ctx, postgres.CreateEmailVerificationTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: ExpiresAt,
	})
}
