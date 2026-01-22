package mfa

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type MFAMethodRepo struct {
	queries *postgres.Queries
}

type MFAChallengeRepo struct {
	queries *postgres.Queries
}

func NewMFAMethodRepo(queries *postgres.Queries) *MFAMethodRepo {
	return &MFAMethodRepo{
		queries: queries,
	}
}

func NewMFAChallengeRepo(queries *postgres.Queries) *MFAChallengeRepo {
	return &MFAChallengeRepo{
		queries: queries,
	}
}

func (m *MFAMethodRepo) Create(ctx context.Context, userID uuid.UUID, secret []byte, methodType MFAMethodType) (MFAMethod, error) {
	postgresMFAMethod, err := m.queries.CreateUserMFAMethod(ctx, postgres.CreateUserMFAMethodParams{
		UserID:           userID,
		Type:             string(methodType),
		SecretCiphertext: secret,
	})
	if err != nil {
		return MFAMethod{}, err
	}

	return toMFAMethod(postgresMFAMethod), nil
}

func (m *MFAMethodRepo) GetConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	rows, err := m.queries.GetMFAMethodsConfirmedByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	methods := make([]MFAMethod, len(rows))
	for i, row := range rows {
		methods[i] = toMFAMethodFromRow(row)
	}

	return methods, nil
}

func (m *MFAMethodRepo) Confirm(ctx context.Context, methodID uuid.UUID) error {
	if err := m.queries.ConfirmUserMFAMethod(ctx, methodID); err != nil {
		return err
	}

	return nil
}

func (m *MFAMethodRepo) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (bool, error) {
	exists, err := m.queries.UserHasActiveMFAMethod(ctx, postgres.UserHasActiveMFAMethodParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (c *MFAChallengeRepo) Create(ctx context.Context, challenge MFAChallenge) error {
	if err := c.queries.CreateChallenge(ctx, postgres.CreateChallengeParams{
		ID:            challenge.ID,
		UserID:        challenge.UserID,
		MfaMethodID:   challenge.MethodID,
		ChallengeType: string(challenge.ChallengeType),
		ExpiresAt:     challenge.ExpiresAt,
	}); err != nil {
		return err
	}

	return nil

}

func (c *MFAChallengeRepo) GetActive(ctx context.Context, id uuid.UUID) (*MFAChallenge, error) {
	postgresChallenge, err := c.queries.GetActiveChallenge(ctx, id)
	if err != nil {
		return nil, err
	}

	return toMFAChallenge(postgresChallenge), nil
}

func (r *MFAChallengeRepo) Consume(ctx context.Context, id uuid.UUID) error {
	if err := r.queries.ConsumeChallenge(ctx, id); err != nil {
		return err
	}

	return nil
}

func toMFAMethod(row postgres.UserMfaMethod) MFAMethod {
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

func toMFAMethodFromRow(row postgres.GetMFAMethodsConfirmedByUserRow) MFAMethod {
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

func toMFAChallenge(row postgres.GetActiveChallengeRow) *MFAChallenge {
	var consumedAt *time.Time
	if row.ConsumedAt.Valid {
		consumedAt = &row.ConsumedAt.Time
	}

	return &MFAChallenge{
		ID:         row.ID,
		UserID:     row.UserID,
		MethodID:   row.MfaMethodID,
		ExpiresAt:  row.ExpiresAt,
		ConsumedAt: consumedAt,
	}
}
