package auth

import (
	"context"
	"time"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/alkuwaiti/auth/internal/mfa"
	"github.com/google/uuid"
)

func (r *repo) userHasActiveMFAMethodByType(ctx context.Context, userID uuid.UUID, methodType mfa.MFAMethodType) (bool, error) {
	exists, err := r.queries.UserHasActiveMFAMethodByType(ctx, postgres.UserHasActiveMFAMethodByTypeParams{
		UserID: userID,
		Type:   string(methodType),
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *repo) deleteExpiredUnconfirmedMethods(ctx context.Context, userID uuid.UUID, methodType mfa.MFAMethodType) error {
	if err := r.queries.DeleteExpiredUnconfirmedMethods(ctx, postgres.DeleteExpiredUnconfirmedMethodsParams{
		UserID: userID,
		Type:   string(methodType),
	}); err != nil {
		return err
	}

	return nil
}

func (r *repo) createUserMFAMethod(ctx context.Context, userID uuid.UUID, secret []byte, methodType mfa.MFAMethodType) (mfa.MFAMethod, error) {
	postgresMFAMethod, err := r.queries.CreateUserMFAMethod(ctx, postgres.CreateUserMFAMethodParams{
		UserID:           userID,
		Type:             string(methodType),
		SecretCiphertext: secret,
	})
	if err != nil {
		return mfa.MFAMethod{}, err
	}

	return toMFAMethod(postgresMFAMethod), nil
}

func (r *repo) getMFAMethodByID(ctx context.Context, methodID uuid.UUID) (mfa.MFAMethod, error) {
	postgresMethod, err := r.queries.GetMFAMethodByID(ctx, methodID)
	if err != nil {
		return mfa.MFAMethod{}, err
	}

	return toMFAMethod(postgresMethod), nil
}

func (r *repo) confirmUserMFAMethod(ctx context.Context, methodID uuid.UUID) error {
	if err := r.queries.ConfirmUserMFAMethod(ctx, methodID); err != nil {
		return err
	}

	return nil
}

func toMFAMethod(row postgres.UserMfaMethod) mfa.MFAMethod {
	var confirmedAt *time.Time
	if row.ConfirmedAt.Valid {
		confirmedAt = &row.ConfirmedAt.Time
	}

	var expiresAt *time.Time
	if row.ExpiresAt.Valid {
		expiresAt = &row.ExpiresAt.Time
	}

	return mfa.MFAMethod{
		ID:          row.ID,
		UserID:      row.UserID,
		Type:        mfa.MFAMethodType(row.Type),
		CreatedAt:   row.CreatedAt,
		Secret:      string(row.SecretCiphertext),
		ConfirmedAt: confirmedAt,
		ExpiresAt:   expiresAt,
	}
}
