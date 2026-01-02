package grpc

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/user"
	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *server) RegisterUser(ctx context.Context, req *userv1.RegisterUserRequest) (*userv1.User, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.userService.RegisterUser(ctx, user.RegisterUserInput{
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

func (s *server) ChangePassword(ctx context.Context, req *userv1.ChangePasswordRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	err := s.authService.ChangePassword(ctx, req.OldPassword, req.NewPassword)
	if err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}
