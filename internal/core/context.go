package core

import (
	"context"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
)

func UserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	raw, ok := ctx.Value(UserIDKey{}).(string)
	if !ok {
		return uuid.Nil, &apperrors.InvalidCredentialsError{}
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, err
	}

	return id, nil
}
