package mfa

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (m *MFARepo) createUserMFAMethod(ctx context.Context, userID uuid.UUID, secret []byte, methodType MFAMethodType) (MFAMethod, error) {
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

func (m *MFARepo) getMFAMethodsConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
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

func (m *MFARepo) confirmUserMFAMethod(ctx context.Context, methodID uuid.UUID) error {
	if err := m.queries.ConfirmUserMFAMethod(ctx, methodID); err != nil {
		return err
	}

	return nil
}

func (m *MFARepo) userHasActiveMFAMethod(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (bool, error) {
	exists, err := m.queries.UserHasActiveMFAMethod(ctx, postgres.UserHasActiveMFAMethodParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (m *MFARepo) getMFAMethodByID(ctx context.Context, methodID uuid.UUID) (MFAMethod, error) {
	postgresMethod, err := m.queries.GetMFAMethodByID(ctx, methodID)
	if err != nil {
		return MFAMethod{}, err
	}

	return toMFAMethod(postgresMethod), nil
}

func (m *MFARepo) DeleteExpiredUnconfirmedMethods(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) error {
	if err := m.queries.DeleteExpiredUnconfirmedMethods(ctx, postgres.DeleteExpiredUnconfirmedMethodsParams{
		UserID: userID,
		Type:   string(methodType),
	}); err != nil {
		return err
	}

	return nil
}

func toMFAMethod(row postgres.UserMfaMethod) MFAMethod {
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		confirmedAt = &row.ConfirmedAt.Time
	}

	var expiresAt *time.Time
	if row.ExpiresAt.Valid {
		expiresAt = &row.ExpiresAt.Time
	}

	return MFAMethod{
		ID:          row.ID,
		UserID:      row.UserID,
		Type:        MFAMethodType(row.Type),
		CreatedAt:   row.CreatedAt,
		Secret:      string(row.SecretCiphertext),
		ConfirmedAt: confirmedAt,
		ExpiresAt:   expiresAt,
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
		CreatedAt:   row.CreatedAt,
		ConfirmedAt: confirmedAt,
	}
}
