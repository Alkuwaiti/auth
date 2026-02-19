package repository

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) UserHasActiveMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) (bool, error) {
	exists, err := r.queries.UserHasActiveMFAMethodByType(ctx, postgres.UserHasActiveMFAMethodByTypeParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *repo) DeleteExpiredUnconfirmedMethods(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) error {
	return r.queries.DeleteExpiredUnconfirmedMethods(ctx, postgres.DeleteExpiredUnconfirmedMethodsParams{
		UserID: userID,
		Type:   string(methodType),
	})
}

func (r *repo) CreateUserMFAMethod(ctx context.Context, userID uuid.UUID, secret []byte, methodType domain.MFAMethodType) (domain.MFAMethod, error) {
	postgresMFAMethod, err := r.queries.CreateUserMFAMethod(ctx, postgres.CreateUserMFAMethodParams{
		UserID:           userID,
		Type:             methodType.String(),
		SecretCiphertext: secret,
	})
	if err != nil {
		return domain.MFAMethod{}, err
	}

	return toMFAMethod(postgresMFAMethod), nil
}

func (r *repo) GetMFAMethodByID(ctx context.Context, methodID uuid.UUID) (domain.MFAMethod, error) {
	postgresMethod, err := r.queries.GetMFAMethodByID(ctx, methodID)
	if err != nil {
		return domain.MFAMethod{}, err
	}

	return toMFAMethod(postgresMethod), nil
}

func (r *repo) ConfirmUserMFAMethod(ctx context.Context, methodID uuid.UUID) error {
	return r.queries.ConfirmUserMFAMethod(ctx, methodID)
}

func (r *repo) GetMFAMethodsConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]domain.MFAMethod, error) {
	rows, err := r.queries.GetMFAMethodsConfirmedByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	methods := make([]domain.MFAMethod, len(rows))
	for i, row := range rows {
		methods[i] = toMFAMethodFromRow(row)
	}

	return methods, nil
}

func (r *repo) GetConfirmedMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType domain.MFAMethodType) (domain.MFAMethod, error) {
	method, err := r.queries.GetConfirmedMFAMethodByType(ctx, postgres.GetConfirmedMFAMethodByTypeParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return domain.MFAMethod{}, err
	}

	return toMFAMethod(method), nil
}

func (r *repo) UserHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := r.queries.UserHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func toMFAMethod(row postgres.UserMfaMethod) domain.MFAMethod {
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		confirmedAt = &row.ConfirmedAt.Time
	}

	var expiresAt *time.Time
	if row.ExpiresAt.Valid {
		expiresAt = &row.ExpiresAt.Time
	}

	return domain.MFAMethod{
		ID:              row.ID,
		UserID:          row.UserID,
		Type:            domain.MFAMethodType(row.Type),
		CreatedAt:       row.CreatedAt,
		EncryptedSecret: string(row.SecretCiphertext),
		ConfirmedAt:     confirmedAt,
		ExpiresAt:       expiresAt,
	}
}

func toMFAMethodFromRow(row postgres.GetMFAMethodsConfirmedByUserRow) domain.MFAMethod {
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		confirmedAt = &row.ConfirmedAt.Time
	}

	return domain.MFAMethod{
		ID:          row.ID,
		UserID:      row.UserID,
		Type:        domain.MFAMethodType(row.Type),
		CreatedAt:   row.CreatedAt,
		ConfirmedAt: confirmedAt,
	}
}
