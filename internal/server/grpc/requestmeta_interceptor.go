package grpc

import (
	"context"

	"github.com/alkuwaiti/auth/internal/observability"
	"google.golang.org/grpc"
)

// TODO: maybe move this to observability sub-package as well.

func RequestMetaInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = observability.WithRequestMeta(ctx, info.FullMethod)
		return handler(ctx, req)
	}
}
