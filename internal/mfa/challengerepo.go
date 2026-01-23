package mfa

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type MFAChallengeRepo struct {
	queries *postgres.Queries
}

func NewMFAChallengeRepo(queries *postgres.Queries) *MFAChallengeRepo {
	return &MFAChallengeRepo{
		queries: queries,
	}
}

func (c *MFAChallengeRepo) Create(ctx context.Context, challenge MFAChallenge) error {
	if err := c.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
		ID:            challenge.ID,
		UserID:        challenge.UserID,
		MfaMethodID:   challenge.MethodID,
		ChallengeType: string(challenge.ChallengeType),
		ExpiresAt:     challenge.ExpiresAt,
	}); err != nil {
		return err
	}

	return nil
}

func (c *MFAChallengeRepo) GetActive(ctx context.Context, id uuid.UUID) (*MFAChallenge, error) {
	postgresChallenge, err := c.queries.GetActiveChallenge(ctx, id)
	if err != nil {
		return nil, err
	}

	return toMFAChallenge(postgresChallenge), nil
}

func (c *MFAChallengeRepo) Consume(ctx context.Context, id uuid.UUID) error {
	if err := c.queries.ConsumeChallenge(ctx, id); err != nil {
		return err
	}

	return nil
}

func toMFAChallenge(row postgres.GetActiveChallengeRow) *MFAChallenge {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		consumedAt = &row.ConsumedAt.Time
	}

	return &MFAChallenge{
		ID:         row.ID,
		UserID:     row.UserID,
		MethodID:   row.MfaMethodID,
		ExpiresAt:  row.ExpiresAt,
		ConsumedAt: consumedAt,
	}
}
