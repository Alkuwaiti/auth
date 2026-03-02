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

func (r *Repo) CreateChallenge(ctx context.Context, challenge domain.MFAChallenge) (domain.MFAChallenge, error) {
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

func (r *Repo) GetChallengeByID(ctx context.Context, challengeID uuid.UUID) (domain.MFAChallenge, error) {
	challenge, err := r.queries.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return domain.MFAChallenge{}, err
	}

	return toMFAChallenge(challenge), nil
}

func (r *Repo) GetActiveTOTPChallengeForUpdate(ctx context.Context, challengeID uuid.UUID) (domain.ActiveTOTPChallenge, error) {
	row, err := r.queries.GetActiveTOTPChallengeForUpdate(ctx, challengeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ActiveTOTPChallenge{}, domain.ErrNotFound
		}
		return domain.ActiveTOTPChallenge{}, err
	}

	return domain.ActiveTOTPChallenge{
		ChallengeID:      row.ChallengeID,
		UserID:           row.UserID,
		MethodID:         row.MethodID,
		Attempts:         int(row.Attempts),
		SecretCiphertext: row.SecretCiphertext,
	}, nil
}

func (r *Repo) IncrementChallengeAttempts(ctx context.Context, challengeID uuid.UUID) error {
	return r.queries.IncrementChallengeAttempts(ctx, challengeID)
}

func (r *Repo) ConsumeChallenge(ctx context.Context, challengeID uuid.UUID) error {
	return r.queries.ConsumeChallenge(ctx, challengeID)
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
