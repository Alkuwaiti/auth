package testutil

import (
	"context"

	"github.com/alkuwaiti/auth/internal/observability"
	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"github.com/google/uuid"
)

func CtxWithRequestMeta(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextkeys.RequestMetaKeyType{}, observability.RequestMeta{
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
	})
}

func CtxWithUserID(ctx context.Context, userID uuid.UUID) context.Context {
	return context.WithValue(ctx, contextkeys.UserIDKey{}, userID.String())
}

func CtxWithEmail(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, contextkeys.EmailKey{}, email)
}

func CtxWithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, contextkeys.RolesKey{}, roles)
}
