package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/google/uuid"
)

func (r *repo) createChallenge(ctx context.Context, challenge mfa.MFAChallenge) (mfa.MFAChallenge, error) {
	postgresChallenge, err := r.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
		UserID:        challenge.UserID,
		MfaMethodID:   challenge.MethodID,
		Scope:         challenge.Scope,
		ChallengeType: string(challenge.ChallengeType),
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	})
	if err != nil {
		return mfa.MFAChallenge{}, err
	}

	return toMFAChallenge(postgresChallenge), nil
}

func (r *repo) getChallengeByID(ctx context.Context, challengeID uuid.UUID) (mfa.MFAChallenge, error) {
	challenge, err := r.queries.GetChallengeByID(ctx, challengeID)
	if err != nil {
		return mfa.MFAChallenge{}, err
	}

	return toMFAChallenge(challenge), nil
}

func toMFAChallenge(row postgres.MfaChallenge) mfa.MFAChallenge {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		consumedAt = &row.ConsumedAt.Time
	}

	return mfa.MFAChallenge{
		ID:         row.ID,
		UserID:     row.UserID,
		MethodID:   row.MfaMethodID,
		ExpiresAt:  row.ExpiresAt,
		Scope:      row.Scope,
		ConsumedAt: consumedAt,
	}
}
