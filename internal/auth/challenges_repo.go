package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) createChallenge(ctx context.Context, challenge MFAChallenge) (MFAChallenge, error) {
	postgresChallenge, err := r.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
		UserID:        challenge.UserID,
		MfaMethodID:   challenge.MethodID,
		Scope:         challenge.Scope.String(),
		ChallengeType: challenge.ChallengeType.String(),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		return MFAChallenge{}, err
	}

	return toMFAChallenge(postgresChallenge), nil
}

func (r *repo) getChallengeByID(ctx context.Context, challengeID uuid.UUID) (MFAChallenge, error) {
	challenge, err := r.queries.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return MFAChallenge{}, err
	}

	return toMFAChallenge(challenge), nil
}

type LockedTOTPChallenge struct {
	ChallengeID      uuid.UUID
	UserID           uuid.UUID
	MethodID         uuid.UUID
	Attempts         int
	SecretCiphertext []byte
}

func (r *repo) lockActiveTOTPChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) (LockedTOTPChallenge, error) {
	row, err := r.queries.WithTx(tx).LockActiveTOTPChallenge(ctx, challengeID)
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

func (r *repo) incrementChallengeAttempts(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return r.queries.WithTx(tx).IncrementChallengeAttempts(ctx, challengeID)
}

func (r *repo) consumeChallenge(ctx context.Context, tx *sql.Tx, challengeID uuid.UUID) error {
	return r.queries.WithTx(tx).ConsumeChallenge(ctx, challengeID)
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
		Scope:      ChallengeScope(row.Scope),
		ConsumedAt: consumedAt,
		Attempts:   int(row.Attempts),
	}
}
