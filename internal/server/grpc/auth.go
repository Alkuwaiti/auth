package grpc

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/core"
	"github.com/alkuwaiti/auth/internal/mfa"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		AccessToken:  res.Tokens.AccessToken,
		RefreshToken: res.Tokens.RefreshToken,
		ExpiresIn:    res.Tokens.RefreshExpiresAt.Unix(),
		TokenType:    "Bearer",
		UserId:       res.Tokens.UserID.String(),
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

	err := s.authService.ChangePassword(ctx, req.OldPassword, req.NewPassword)
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

func (s *server) DeleteUser(ctx context.Context, req *authv1.DeleteUserRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user id is not a uuid")
	}

	actorID, err := core.UserIDFromContext(ctx)
	if err != nil {
		return &emptypb.Empty{}, MapError(err)
	}

	// TODO: fix this so that actorID is gotten from context in the service.
	err = s.authService.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         userID,
		ActorID:        actorID,
		DeletionReason: auth.DeletionReason(req.Reason),
		Note:           req.Note,
	})
	if err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *server) EnrollMFAMethod(ctx context.Context, req *authv1.EnrollMFAMethodRequest) (*authv1.EnrollMFAMethodResponse, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.authService.EnrollMFAMethod(ctx, mfa.MFAMethodType(req.Method))
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.EnrollMFAMethodResponse{
		Method: &authv1.MFAMethod{
			Id:        res.Method.ID.String(),
			Type:      string(res.Method.Type),
			CreatedAt: timestamppb.New(res.Method.CreatedAt),
		},
		SetupUri: res.SetupURI,
	}, nil
}

func (s *server) ConfirmMFAMethod(ctx context.Context, req *authv1.ConfirmMFAMethodRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	methodID, err := uuid.Parse(req.MethodId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user id is not a uuid")
	}

	err = s.authService.ConfirmMethod(ctx, methodID, req.Code)
	if err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}
