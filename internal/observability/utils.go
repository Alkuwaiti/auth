package observability

import (
	"context"
	"net"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const (
	headerClientIP      = "x-client-ip"
	headerClientUA      = "x-client-user-agent"
	headerUserAgent     = "user-agent"
	headerXForwardedFor = "x-forwarded-for"
	headerRequestID     = "request-id"
)

type RequestMetaKeyType struct{}

// TODO: change this function when you have an api-gateway.

func ExtractRequestMeta(ctx context.Context) RequestMeta {
	md, _ := metadata.FromIncomingContext(ctx)

	meta := RequestMeta{
		XForwardedFor: first(md.Get(headerXForwardedFor)),
		// RequestID:     first(md.Get(headerRequestID)),
	}

	// Preferred: gateway-injected client metadata
	if ip := first(md.Get(headerClientIP)); ip != "" {
		meta.IPAddress = ip
		meta.UserAgent = first(md.Get(headerClientUA))
		return meta
	}

	// Fallback: direct gRPC client
	if p, ok := peer.FromContext(ctx); ok {
		if tcp, ok := p.Addr.(*net.TCPAddr); ok {
			meta.IPAddress = tcp.IP.String()
		}
	}

	meta.UserAgent = first(md.Get(headerUserAgent))

	return meta
}

func RequestMetaFromContext(ctx context.Context) RequestMeta {
	if meta, ok := ctx.Value(RequestMetaKeyType{}).(RequestMeta); ok {
		return meta
	}
	return RequestMeta{}
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

func WithRequestMeta(ctx context.Context, methodName string) context.Context {
	meta := ExtractRequestMeta(ctx)

	span := trace.SpanFromContext(ctx)
	if sc := span.SpanContext(); sc.IsValid() {
		meta.TraceID = sc.TraceID().String()
		meta.SpanID = sc.SpanID().String()
		meta.RequestMethod = methodName
	}

	return context.WithValue(ctx, RequestMetaKeyType{}, meta)
}
