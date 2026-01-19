package core

import (
	"context"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/observability"
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

func UserRolesFromContext(ctx context.Context) ([]string, error) {
	roles, ok := ctx.Value(RolesKey{}).([]string)
	if !ok {
		return nil, &apperrors.InvalidCredentialsError{}
	}

	return roles, nil
}

func RequestMetaFromContext(ctx context.Context) observability.RequestMeta {
	meta, ok := ctx.Value(RequestMetaKeyType{}).(observability.RequestMeta)
	if !ok {
		return observability.RequestMeta{}
	}

	return meta
}
