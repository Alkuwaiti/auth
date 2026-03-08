package repository

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
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

func (r *Repo) GetWebAuthnChallengeByUserID(ctx context.Context, userID uuid.UUID) (domain.WebAuthnChallenge, error) {
	challenge, err := r.queries.GetWebAuthnChallengeByUserID(ctx, userID)
	if err != nil {
		return domain.WebAuthnChallenge{}, err
	}

	return domain.WebAuthnChallenge{
		Challenge: challenge.Challenge,
		UserID:    challenge.UserID,
		ExpiresAt: challenge.ExpiresAt,
	}, nil
}

func (r *Repo) CreatePasskey(ctx context.Context, userID uuid.UUID, credentialID []byte, publicKey []byte, signCount int64, transports []string) error {
	return r.queries.CreatePasskey(ctx, postgres.CreatePasskeyParams{
		UserID:       userID,
		CredentialID: credentialID,
		SignCount:    signCount,
		PublicKey:    publicKey,
		Transports:   transports,
	})
}

func (r *Repo) DeleteWebAuthnChallenge(ctx context.Context, userID uuid.UUID) error {
	return r.queries.DeleteWebAuthnChallenge(ctx, userID)
}
