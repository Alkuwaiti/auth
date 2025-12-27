package grpc

import (
	"context"
	"log/slog"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.TokenPair, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	meta := RequestMetaFromContext(ctx)

	res, err := s.authService.Login(ctx, req.Email, req.Password, meta)
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.TokenPair{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    res.RefreshExpiresAt.Unix(),
		TokenType:    "Bearer",
		UserId:       res.UserID.String(),
	}, nil
}

func (s *server) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.TokenPair, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	meta := RequestMetaFromContext(ctx)

	res, err := s.authService.RefreshToken(ctx, req.RefreshToken, meta)
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.TokenPair{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    res.RefreshExpiresAt.Unix(),
		TokenType:    "Bearer",
		UserId:       res.UserID.String(),
	}, nil
}
