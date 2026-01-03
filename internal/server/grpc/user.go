package grpc

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth"
	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) RegisterUser(ctx context.Context, req *userv1.RegisterUserRequest) (*userv1.User, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.authService.RegisterUser(ctx, auth.RegisterUserInput{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, MapError(err)
	}

	return &userv1.User{
		Id:       res.ID.String(),
		Username: res.Username,
		Email:    res.Email,
	}, nil
}
