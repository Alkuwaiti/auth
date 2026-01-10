package grpc

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/core"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (s *server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.TokenPair, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.authService.Login(ctx, req.Email, req.Password)
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

	res, err := s.authService.RefreshToken(ctx, req.RefreshToken)
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

func (s *server) Logout(ctx context.Context, req *authv1.RefreshTokenRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	err := s.authService.Logout(ctx, req.RefreshToken)
	if err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *server) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	userID, err := core.UserIDFromContext(ctx)
	if err != nil {
		return &emptypb.Empty{}, MapError(err)
	}

	err = s.authService.ChangePassword(ctx, userID, req.OldPassword, req.NewPassword)
	if err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *server) RegisterUser(ctx context.Context, req *authv1.RegisterUserRequest) (*authv1.User, error) {
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

	return &authv1.User{
		Id:       res.ID.String(),
		Username: res.Username,
		Email:    res.Email,
	}, nil
}
