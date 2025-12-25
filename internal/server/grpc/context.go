package grpc

import (
	"context"
	"net"

	"github.com/alkuwaiti/auth/internal/core"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

type requestMetaKeyType struct{}

var requestMetaKey = requestMetaKeyType{}

func ExtractRequestMeta(ctx context.Context) core.RequestMeta {
	md, _ := metadata.FromIncomingContext(ctx)

	// 1️⃣ Preferred: gateway-injected metadata
	if ip := md.Get("x-client-ip"); len(ip) > 0 {
		ua := ""
		if v := md.Get("x-client-user-agent"); len(v) > 0 {
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

	if ua := md.Get("user-agent"); len(ua) > 0 {
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
