package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type repo struct {
	queries *postgres.Queries
}

func NewRepo(queries *postgres.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) CreateSession(ctx context.Context, userID uuid.UUID, refreshTokenHash string, expiry time.Time) error {
	err := r.queries.CreateSession(ctx, postgres.CreateSessionParams{
		UserID:           userID,
		RefreshTokenHash: refreshTokenHash,
		UserAgent:        "",
		IpAddress:        "",
		ExpiresAt:        expiry,
	})
	if err != nil {
		return err
	}

	return nil
}
