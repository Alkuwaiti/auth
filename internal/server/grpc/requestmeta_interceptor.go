package grpc

import (
	"context"

	"github.com/alkuwaiti/auth/internal/observability"
	"google.golang.org/grpc"
)

// TODO: maybe move this to observability sub-package as well.

type RequestMetaInterceptor struct{}

func NewRequestMetaInterceptor() *RequestMetaInterceptor {
	return &RequestMetaInterceptor{}
}

func (i *RequestMetaInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = observability.WithRequestMeta(ctx, info.FullMethod)
		return handler(ctx, req)
	}
}
