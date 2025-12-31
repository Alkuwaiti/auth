package grpc

import (
	"context"

	"github.com/alkuwaiti/auth/internal/observability"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

func LoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {

		meta := observability.ExtractRequestMeta(ctx)

		span := trace.SpanFromContext(ctx)
		if sc := span.SpanContext(); sc.IsValid() {
			meta.TraceID = sc.TraceID().String()
			meta.SpanID = sc.SpanID().String()
			meta.RequestMethod = info.FullMethod
		}

		ctx = context.WithValue(ctx, observability.RequestMetaKey, meta)

		return handler(ctx, req)
	}
}
