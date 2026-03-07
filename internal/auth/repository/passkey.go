package repository

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *Repo) ListPasskeysByUserID(ctx context.Context, userID uuid.UUID) ([][]byte, error) {
	return r.queries.ListPasskeysByUserID(ctx, userID)
}

func (r *Repo) CreateWebAuthnChallenge(ctx context.Context, challenge []byte, userID uuid.UUID, expiresAt time.Time) error {
	return r.queries.CreateWebAuthnChallenge(ctx, postgres.CreateWebAuthnChallengeParams{
		Challenge: challenge,
		UserID:    userID,
		ExpiresAt: expiresAt,
	})
}

func (r *Repo) GetWebAuthnChallengeByUserID(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	challenge, err := r.queries.GetWebAuthnChallengeByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	return challenge.Challenge, nil
}
