package grpc

import (
	"context"

	"github.com/alkuwaiti/auth/pkg/contextkeys"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

type RequestMetaInterceptor struct{}

func NewRequestMetaInterceptor() *RequestMetaInterceptor {
	return &RequestMetaInterceptor{}
}

func (i *RequestMetaInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = withRequestMeta(ctx, info.FullMethod)
		return handler(ctx, req)
	}
}

func withRequestMeta(ctx context.Context, methodName string) context.Context {
	meta := contextkeys.ExtractRequestMeta(ctx)

	span := trace.SpanFromContext(ctx)
	if sc := span.SpanContext(); sc.IsValid() {
		meta.TraceID = sc.TraceID().String()
		meta.SpanID = sc.SpanID().String()
		meta.RequestMethod = methodName
	}

	return context.WithValue(ctx, contextkeys.RequestMetaKeyType{}, meta)
}
