package grpc

import (
	"context"
	"net"

	"github.com/alkuwaiti/auth/internal/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const (
	headerClientIP  = "x-client-ip"
	headerClientUA  = "x-client-user-agent"
	headerUserAgent = "user-agent"
)

type requestMetaKeyType struct{}

var requestMetaKey = requestMetaKeyType{}

// RequestMetaInterceptor enriches the context with request metadata.
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

func ExtractRequestMeta(ctx context.Context) core.RequestMeta {
	md, _ := metadata.FromIncomingContext(ctx)

	// 1️⃣ Preferred: gateway-injected metadata
	if ip := md.Get(headerClientIP); len(ip) > 0 {
		ua := ""
		if v := md.Get(headerClientUA); len(v) > 0 {
			ua = v[0]
		}

		return core.RequestMeta{
			IPAddress: ip[0],
			UserAgent: ua,
		}
	}

	// 2️⃣ Fallback: direct gRPC call (no gateway yet)
	meta := core.RequestMeta{}

	if p, ok := peer.FromContext(ctx); ok {
		if tcp, ok := p.Addr.(*net.TCPAddr); ok {
			meta.IPAddress = tcp.IP.String()
		}
	}

	if ua := md.Get(headerUserAgent); len(ua) > 0 {
		meta.UserAgent = ua[0]
	}

	return meta
}

func RequestMetaFromContext(ctx context.Context) core.RequestMeta {
	if meta, ok := ctx.Value(requestMetaKey).(core.RequestMeta); ok {
		return meta
	}
	return core.RequestMeta{}
}
