package testutil

import (
	"context"

	"github.com/alkuwaiti/auth/internal/observability"
)

func CtxWithRequestMeta() context.Context {
	ctx := context.Background()

	return context.WithValue(ctx, observability.RequestMetaKeyType{}, observability.RequestMeta{
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
	})
}
