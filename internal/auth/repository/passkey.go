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

func (r *Repo) CreateWebAuthnChallenge(ctx context.Context, challenge []byte, userID uuid.NullUUID, expiresAt time.Time) error {
	return r.queries.CreateWebAuthnChallenge(ctx, postgres.CreateWebAuthnChallengeParams{
		Challenge: challenge,
		UserID:    userID,
		ExpiresAt: expiresAt,
	})
}

func (r *Repo) GetWebAuthnChallenge(ctx context.Context, challengeBytes []byte) (domain.WebAuthnChallenge, error) {
	challenge, err := r.queries.GetWebAuthnChallenge(ctx, challengeBytes)
	if err != nil {
		return domain.WebAuthnChallenge{}, err
	}

	return domain.WebAuthnChallenge{
		Challenge: challenge.Challenge,
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

func (r *Repo) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (domain.Passkey, error) {
	passkey, err := r.queries.GetPasskeyByCredentialID(ctx, credentialID)
	if err != nil {
		return domain.Passkey{}, err
	}

	return domain.Passkey{
		ID:        passkey.ID,
		PublicKey: passkey.PublicKey,
		UserID:    passkey.UserID,
	}, nil
}

func (r *Repo) UpdatePasskeySignCount(ctx context.Context, passkeyID uuid.UUID, signCount int64) error {
	return r.queries.UpdatePasskeySignCount(ctx, postgres.UpdatePasskeySignCountParams{
		ID:        passkeyID,
		SignCount: signCount,
	})
}
