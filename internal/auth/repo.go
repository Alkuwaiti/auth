package auth

import (
	"context"
	"database/sql"
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

func (r *repo) CreateSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshTokenHash, IPAddress, userAgent string) error {
	err := r.queries.CreateSession(ctx, postgres.CreateSessionParams{
		UserID:           userID,
		RefreshTokenHash: refreshTokenHash,
		UserAgent: sql.NullString{
			String: userAgent,
			Valid:  userAgent != "",
		},
		IpAddress: sql.NullString{
			String: IPAddress,
			Valid:  IPAddress != "",
		},
		ExpiresAt: expiry,
	})
	if err != nil {
		return err
	}

	return nil
}
