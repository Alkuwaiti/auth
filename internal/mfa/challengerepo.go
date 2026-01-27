package mfa

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type MFAChallengeRepo struct {
	queries *postgres.Queries
	db      *sql.DB
}

func NewMFAChallengeRepo(db *sql.DB) *MFAChallengeRepo {
	return &MFAChallengeRepo{
		db:      db,
		queries: postgres.New(db),
	}
}

func (c *MFAChallengeRepo) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return c.db.BeginTx(ctx, nil)
}

func (c *MFAChallengeRepo) Create(ctx context.Context, challenge MFAChallenge) (MFAChallenge, error) {
	postgresChallenge, err := c.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
		UserID:        challenge.UserID,
		MfaMethodID:   challenge.MethodID,
		ChallengeType: string(challenge.ChallengeType),
		ExpiresAt:     challenge.ExpiresAt,
	})
	if err != nil {
		return MFAChallenge{}, err
	}

	return toMFAChallenge(postgresChallenge), nil
}

func (c *MFAChallengeRepo) GetActive(ctx context.Context, id uuid.UUID) (MFAChallenge, error) {
	postgresChallenge, err := c.queries.GetActiveChallenge(ctx, id)
	if err != nil {
		return MFAChallenge{}, err
	}

	return toMFAChallengeFromActive(postgresChallenge), nil
}

func (c *MFAChallengeRepo) LockActiveTOTPChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) (LockedTOTPChallenge, error) {
	q := c.queries.WithTx(tx)

	row, err := q.LockActiveTOTPChallenge(ctx, challengeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return LockedTOTPChallenge{}, ErrInvalidMFAChallenge
		}
		return LockedTOTPChallenge{}, err
	}

	return LockedTOTPChallenge{
		ChallengeID:      row.ChallengeID,
		UserID:           row.UserID,
		MethodID:         row.MethodID,
		SecretCiphertext: row.SecretCiphertext,
	}, nil
}

func (c *MFAChallengeRepo) ConsumeChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return c.queries.WithTx(tx).ConsumeChallenge(ctx, challengeID)
}

func toMFAChallenge(row postgres.MfaChallenge) MFAChallenge {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		consumedAt = &row.ConsumedAt.Time
	}

	return MFAChallenge{
		ID:         row.ID,
		UserID:     row.UserID,
		MethodID:   row.MfaMethodID,
		ExpiresAt:  row.ExpiresAt,
		ConsumedAt: consumedAt,
	}
}

func toMFAChallengeFromActive(row postgres.GetActiveChallengeRow) MFAChallenge {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		consumedAt = &row.ConsumedAt.Time
	}

	return MFAChallenge{
		ID:         row.ID,
		UserID:     row.UserID,
		MethodID:   row.MfaMethodID,
		ExpiresAt:  row.ExpiresAt,
		ConsumedAt: consumedAt,
	}
}
