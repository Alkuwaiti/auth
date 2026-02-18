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

func (r *repo) CreateChallenge(ctx context.Context, challenge domain.MFAChallenge) (domain.MFAChallenge, error) {
	postgresChallenge, err := r.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
		UserID:        challenge.UserID,
		MfaMethodID:   challenge.MethodID,
		Scope:         challenge.Scope.String(),
		ChallengeType: challenge.ChallengeType.String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		return domain.MFAChallenge{}, err
	}

	return toMFAChallenge(postgresChallenge), nil
}

func (r *repo) GetChallengeByID(ctx context.Context, challengeID uuid.UUID) (domain.MFAChallenge, error) {
	challenge, err := r.queries.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return domain.MFAChallenge{}, err
	}

	return toMFAChallenge(challenge), nil
}

func (r *repo) LockActiveTOTPChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) (domain.LockedTOTPChallenge, error) {
	row, err := r.queries.WithTx(tx).LockActiveTOTPChallenge(ctx, challengeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.LockedTOTPChallenge{}, domain.ErrNotFound
		}
		return domain.LockedTOTPChallenge{}, err
	}

	return domain.LockedTOTPChallenge{
		ChallengeID:      row.ChallengeID,
		UserID:           row.UserID,
		MethodID:         row.MethodID,
		Attempts:         int(row.Attempts),
		SecretCiphertext: row.SecretCiphertext,
	}, nil
}

func (r *repo) IncrementChallengeAttempts(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return r.queries.WithTx(tx).IncrementChallengeAttempts(ctx, challengeID)
}

func (r *repo) ConsumeChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return r.queries.WithTx(tx).ConsumeChallenge(ctx, challengeID)
}

func toMFAChallenge(row postgres.MfaChallenge) domain.MFAChallenge {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		consumedAt = &row.ConsumedAt.Time
	}

	return domain.MFAChallenge{
		ID:         row.ID,
		UserID:     row.UserID,
		MethodID:   row.MfaMethodID,
		ExpiresAt:  row.ExpiresAt,
		Scope:      domain.ChallengeScope(row.Scope),
		ConsumedAt: consumedAt,
		Attempts:   int(row.Attempts),
	}
}
