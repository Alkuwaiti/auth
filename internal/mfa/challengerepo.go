package mfa

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type MFARepo struct {
	queries *postgres.Queries
	db      *sql.DB
}

func NewMFARepo(db *sql.DB) *MFARepo {
	return &MFARepo{
		db:      db,
		queries: postgres.New(db),
	}
}

func (m *MFARepo) beginTx(ctx context.Context) (*sql.Tx, error) {
	return m.db.BeginTx(ctx, nil)
}

func (m *MFARepo) lockActiveTOTPChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) (LockedTOTPChallenge, error) {
	q := m.queries.WithTx(tx)

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
		Attempts:         int(row.Attempts),
		SecretCiphertext: row.SecretCiphertext,
	}, nil
}

func (m *MFARepo) incrementChallengeAttempts(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return m.queries.WithTx(tx).IncrementChallengeAttempts(ctx, challengeID)
}

func (m *MFARepo) consumeChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return m.queries.WithTx(tx).ConsumeChallenge(ctx, challengeID)
}
