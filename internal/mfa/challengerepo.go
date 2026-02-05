package mfa

import (
	"context"
	"database/sql"
	"errors"
	"time"

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

func (m *MFARepo) createChallenge(ctx context.Context, challenge MFAChallenge) (MFAChallenge, error) {
	postgresChallenge, err := m.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
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

func (m *MFARepo) getChallengeByID(ctx context.Context, challengeID uuid.UUID) (MFAChallenge, error) {
	challenge, err := m.queries.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return MFAChallenge{}, err
	}

	return toMFAChallenge(challenge), nil
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
		SecretCiphertext: row.SecretCiphertext,
	}, nil
}

func (m *MFARepo) consumeChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return m.queries.WithTx(tx).ConsumeChallenge(ctx, challengeID)
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
