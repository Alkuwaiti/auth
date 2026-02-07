package grpc

import (
	"context"
	"errors"
	"strings"

	"github.com/alkuwaiti/auth/internal/contextkeys"
	"github.com/alkuwaiti/auth/internal/tokens"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var publicMethods = map[string]struct{}{
	"/auth.v1.AuthService/Login":            {},
	"/auth.v1.AuthService/RegisterUser":     {},
	"/auth.v1.AuthService/RefreshToken":     {},
	"/auth.v1.AuthService/Logout":           {},
	"/auth.v1.AuthService/CompleteLoginMFA": {},
}

type JWTValidator interface {
	ValidateJWT(token string) (*tokens.AccessClaims, error)
}

type AuthInterceptor struct {
	validator JWTValidator
}

func NewAuthInterceptor(tm JWTValidator) *AuthInterceptor {
	return &AuthInterceptor{validator: tm}
}

func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {

		// 1. Skip auth for public endpoints
		if _, ok := publicMethods[info.FullMethod]; ok {
			return handler(ctx, req)
		}

		// 2. Otherwise enforce JWT
		tokenStr, err := extractBearerToken(ctx)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}

		claims, err := i.validator.ValidateJWT(tokenStr)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		ctx = context.WithValue(ctx, contextkeys.EmailKey{}, claims.Email)
		ctx = context.WithValue(ctx, contextkeys.UserIDKey{}, claims.Subject)
		ctx = context.WithValue(ctx, contextkeys.RolesKey{}, claims.Roles)

		return handler(ctx, req)
	}
}

func extractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("no metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return "", errors.New("no authorization header")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(values[0], prefix) {
		return "", errors.New("invalid auth header")
	}

	return strings.TrimPrefix(values[0], prefix), nil
}
