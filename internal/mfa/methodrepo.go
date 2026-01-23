package mfa

import (
	"context"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type MFAMethodRepo struct {
	queries *postgres.Queries
}

func NewMFAMethodRepo(queries *postgres.Queries) *MFAMethodRepo {
	return &MFAMethodRepo{
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

func (m *MFAMethodRepo) GetByID(ctx context.Context, methodID uuid.UUID) (MFAMethod, error) {
	postgresMethod, err := m.queries.GetMFAMethodByID(ctx, methodID)
	if err != nil {
		return MFAMethod{}, err
	}

	return toMFAMethod(postgresMethod), nil
}
