package grpc

import (
	"context"

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

		meta := ExtractRequestMeta(ctx)

		span := trace.SpanFromContext(ctx)
		if sc := span.SpanContext(); sc.IsValid() {
			meta.TraceID = sc.TraceID().String()
			meta.SpanID = sc.SpanID().String()
		}

		ctx = context.WithValue(ctx, requestMetaKey, meta)

		return handler(ctx, req)
	}
}
