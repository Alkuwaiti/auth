package grpc

import (
	"context"

	"google.golang.org/grpc"
)

func RequestMetaInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {

		meta := ExtractRequestMeta(ctx)

		ctx = context.WithValue(ctx, requestMetaKey, meta)

		return handler(ctx, req)
	}
}
