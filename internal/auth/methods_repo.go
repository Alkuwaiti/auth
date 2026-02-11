package auth

import (
	"context"
	"database/sql"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) userHasActiveMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (bool, error) {
	exists, err := r.queries.UserHasActiveMFAMethodByType(ctx, postgres.UserHasActiveMFAMethodByTypeParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *repo) deleteExpiredUnconfirmedMethods(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) error {
	return r.queries.DeleteExpiredUnconfirmedMethods(ctx, postgres.DeleteExpiredUnconfirmedMethodsParams{
		UserID: userID,
		Type:   string(methodType),
	})
}

func (r *repo) createUserMFAMethod(ctx context.Context, userID uuid.UUID, secret []byte, methodType MFAMethodType) (MFAMethod, error) {
	postgresMFAMethod, err := r.queries.CreateUserMFAMethod(ctx, postgres.CreateUserMFAMethodParams{
		UserID:           userID,
		Type:             methodType.String(),
		SecretCiphertext: secret,
	})
	if err != nil {
		return MFAMethod{}, err
	}

	return toMFAMethod(postgresMFAMethod), nil
}

func (r *repo) getMFAMethodByID(ctx context.Context, methodID uuid.UUID) (MFAMethod, error) {
	postgresMethod, err := r.queries.GetMFAMethodByID(ctx, methodID)
	if err != nil {
		return MFAMethod{}, err
	}

	return toMFAMethod(postgresMethod), nil
}

func (r *repo) confirmUserMFAMethod(ctx context.Context, tx *sql.Tx, methodID uuid.UUID) error {
	return r.queries.WithTx(tx).ConfirmUserMFAMethod(ctx, methodID)
}

func (r *repo) getMFAMethodsConfirmedByUser(ctx context.Context, userID uuid.UUID) ([]MFAMethod, error) {
	rows, err := r.queries.GetMFAMethodsConfirmedByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	methods := make([]MFAMethod, len(rows))
	for i, row := range rows {
		methods[i] = toMFAMethodFromRow(row)
	}

	return methods, nil
}

func (r *repo) getConfirmedMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType MFAMethodType) (MFAMethod, error) {
	method, err := r.queries.GetConfirmedMFAMethodByType(ctx, postgres.GetConfirmedMFAMethodByTypeParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return MFAMethod{}, err
	}

	return toMFAMethod(method), nil
}

func (r *repo) userHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := r.queries.UserHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
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
		ID:              row.ID,
		UserID:          row.UserID,
		Type:            MFAMethodType(row.Type),
		CreatedAt:       row.CreatedAt,
		EncryptedSecret: string(row.SecretCiphertext),
		ConfirmedAt:     confirmedAt,
		ExpiresAt:       expiresAt,
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
