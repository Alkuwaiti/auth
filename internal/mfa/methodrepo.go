package mfa

import (
	"context"

	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (m *MFARepo) userHasActiveMFAMethod(ctx context.Context, userID uuid.UUID) (bool, error) {
	exists, err := m.queries.UserHasActiveMFAMethod(ctx, userID)
	if err != nil {
		return false, err
	}

	return exists, nil
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
