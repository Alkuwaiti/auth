package grpc

import (
	"context"
	"log/slog"

	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	meta := RequestMetaFromContext(ctx)

	res, err := s.authService.Login(ctx, req.Email, req.Password, meta)
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.LoginResponse{
		AccessToken:  res.AccessToken,
		RefreshToken: res.RefreshToken,
		ExpiresIn:    res.RefreshExpiresAt.Unix(),
		TokenType:    "Bearer",
		UserId:       res.UserID.String(),
	}, nil
}
