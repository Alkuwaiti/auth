package mfa

import (
	"context"
	"time"

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

func NewRepo(queries *postgres.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) CreateUserMFAMethod(ctx context.Context, method MFAMethod) error {
	if err := r.queries.CreateUserMFAMethod(ctx, postgres.CreateUserMFAMethodParams{
		ID:               method.ID,
		UserID:           method.UserID,
		Type:             string(method.Type),
		SecretCiphertext: []byte(method.Secret),
	}); err != nil {
		return err
	}

	return nil
}

func (r *repo) GetMFAMethodsConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	rows, err := r.queries.GetMFAMethodsConfirmedByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	methods := make([]MFAMethod, len(rows))
	for i, row := range rows {
		methods[i] = toMFAMethod(row)
	}

	return methods, nil
}

func (r *repo) ConfirmUserMFAMethod(ctx context.Context, methodID uuid.UUID) error {
	panic("unimplemented")
}

func (r *repo) CreateChallenge(ctx context.Context, c MFAChallenge) error {
	panic("unimplemented")
}

func (r *repo) GetActiveChallenges(ctx context.Context, id uuid.UUID) (*MFAChallenge, error) {
	panic("unimplemented")
}

func (r *repo) ConsumeChallenge(ctx context.Context, id uuid.UUID) error {
	panic("unimplemented")
}

func toMFAMethod(row postgres.GetMFAMethodsConfirmedByUserRow) MFAMethod {
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		confirmedAt = &row.ConfirmedAt.Time
	}

	return MFAMethod{
		ID:          row.ID,
		UserID:      row.UserID,
		Type:        MFAMethodType(row.Type),
		ConfirmedAt: confirmedAt,
	}
}
