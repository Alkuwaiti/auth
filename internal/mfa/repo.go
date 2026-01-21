package mfa

import (
	"context"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type MFAMethodRepo interface {
	Create(ctx context.Context, method MFAMethod) error
	GetConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error)
	Confirm(ctx context.Context, methodID uuid.UUID) error
}

type MFAChallengeRepo interface {
	Create(ctx context.Context, c MFAChallenge) error
	GetActive(ctx context.Context, id uuid.UUID) (*MFAChallenge, error)
	Consume(ctx context.Context, id uuid.UUID) error
}

type repo struct {
	queries *postgres.Queries
}
