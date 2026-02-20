package contextkeys

import (
	"context"
	"net"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func UserIDFromContext(ctx context.Context) (uuid.UUID, error) {
	raw, ok := ctx.Value(UserIDKey{}).(string)
	if !ok {
		return uuid.Nil, ErrMissingUserID
	}

	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, err
	}

	return id, nil
}

func UserRolesFromContext(ctx context.Context) ([]string, error) {
	roles, ok := ctx.Value(RolesKey{}).([]string)
	if !ok {
		return nil, ErrMissingUserRoles
	}

	return roles, nil
}

func UserEmailFromContext(ctx context.Context) (string, error) {
	email, ok := ctx.Value(EmailKey{}).(string)
	if !ok {
		return "", ErrMissingUserEmail
	}

	return email, nil
}

// TODO: move ctx key here.

func RequestMetaFromContext(ctx context.Context) RequestMeta {
	meta, ok := ctx.Value(RequestMetaKeyType{}).(RequestMeta)
	if !ok {
		return RequestMeta{}
	}

	return meta
}

const (
	headerClientIP      = "x-client-ip"
	headerClientUA      = "x-client-user-agent"
	headerUserAgent     = "user-agent"
	headerXForwardedFor = "x-forwarded-for"
	headerRequestID     = "request-id"
)

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

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}
