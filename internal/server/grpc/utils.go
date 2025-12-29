package grpc

import (
	"context"
	"net"

	"github.com/alkuwaiti/auth/internal/core"
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

type requestMetaKeyType struct{}

var requestMetaKey = requestMetaKeyType{}

// TODO: change this function when you have an api-gateway.

func ExtractRequestMeta(ctx context.Context) core.RequestMeta {
	md, _ := metadata.FromIncomingContext(ctx)

	meta := core.RequestMeta{
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

func RequestMetaFromContext(ctx context.Context) core.RequestMeta {
	if meta, ok := ctx.Value(requestMetaKey).(core.RequestMeta); ok {
		return meta
	}
	return core.RequestMeta{}
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
