package grpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/alkuwaiti/auth/internal/core"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var publicMethods = map[string]struct{}{
	"/auth.v1.AuthService/Login":        {},
	"/auth.v1.UserService/RegisterUser": {},
	"/auth.v1.AuthService/RefreshToken": {},
}

type AccessClaims struct {
	UserID uuid.UUID `json:"sub"`
	jwt.StandardClaims
}

func AuthUnaryInterceptor(
	jwtKey []byte,
	issuer string,
	audience string,
) grpc.UnaryServerInterceptor {

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

		claims, err := validateJWT(tokenStr, jwtKey, issuer, audience)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		ctx = context.WithValue(ctx, core.UserIDKey{}, claims.UserID)

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

func validateJWT(
	tokenStr string,
	key []byte,
	issuer string,
	audience string,
) (*AccessClaims, error) {

	token, err := jwt.ParseWithClaims(
		tokenStr,
		&AccessClaims{},
		func(t *jwt.Token) (any, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method")
			}
			return key, nil
		},
	)
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}

	// Explicit claim checks
	if !claims.VerifyIssuer(issuer, true) {
		return nil, errors.New("invalid issuer")
	}

	if !claims.VerifyAudience(audience, true) {
		return nil, errors.New("invalid audience")
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return claims, nil
}
