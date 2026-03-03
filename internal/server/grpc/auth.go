package grpc

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth"
	"github.com/alkuwaiti/auth/internal/auth/domain"
	authv1 "github.com/alkuwaiti/auth/pb/pbauth/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *server) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.service.Login(ctx, req.Email, req.Password)
	if err != nil {
		return nil, MapError(err)
	}

	response := &authv1.LoginResponse{
		MfaRequired: res.RequiresMFA,
	}

	if res.ChallengeID != nil {
		response.ChallengeId = res.ChallengeID.String()
	}

	// Only populate tokens if they exist
	if res.Tokens != nil {
		response.Tokens = &authv1.TokenPair{
			AccessToken:  res.Tokens.AccessToken,
			RefreshToken: res.Tokens.RefreshToken,
			ExpiresIn:    res.Tokens.RefreshExpiresAt.Unix(),
			TokenType:    "Bearer",
			UserId:       res.Tokens.UserID.String(),
		}
	}
	return response, nil
}

func (s *server) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.TokenPair, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.service.RefreshToken(ctx, req.RefreshToken)
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

	err := s.service.Logout(ctx, req.RefreshToken)
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

	err := s.service.ChangePassword(ctx, req.OldPassword, req.NewPassword)
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

	res, err := s.service.RegisterUser(ctx, auth.RegisterUserInput{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.User{
		Id:    res.ID.String(),
		Email: res.Email,
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

	err = s.service.DeleteUser(ctx, auth.DeleteUserInput{
		UserID:         userID,
		DeletionReason: domain.DeletionReason(req.Reason),
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

	res, err := s.service.EnrollMFAMethod(ctx, domain.MFAMethodType(req.Method))
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

func (s *server) ConfirmMFAMethod(ctx context.Context, req *authv1.ConfirmMFAMethodRequest) (*authv1.ConfirmMFAMethodResponse, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	methodID, err := uuid.Parse(req.MethodId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "user id is not a uuid")
	}

	backupCodes, err := s.service.ConfirmMFAMethod(ctx, methodID, req.Code)
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.ConfirmMFAMethodResponse{
		BackupCodes: backupCodes,
	}, nil
}

func (s *server) CompleteLoginMFA(ctx context.Context, req *authv1.CompleteLoginMFARequest) (*authv1.TokenPair, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	challengeID, err := uuid.Parse(req.ChallengeId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "challenge id is not a uuid")
	}

	res, err := s.service.CompleteLoginMFA(ctx, challengeID, req.Code)
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

func (s *server) CreateStepUpChallenge(ctx context.Context, req *authv1.CreateStepUpChallengeRequest) (*authv1.CreateStepUpChallengeResponse, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.service.CreateStepUpChallenge(ctx, domain.MFAMethodType(req.MethodType), domain.ChallengeScope(req.Scope))
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.CreateStepUpChallengeResponse{
		ChallengeId: res.ChallengeID.String(),
		MethodType:  string(res.MFAMethodType),
		ExpiresAt:   timestamppb.New(res.ExpiresAt),
	}, nil
}

func (s *server) VerifyStepUpChallenge(ctx context.Context, req *authv1.VerifyStepUpChallengeRequest) (*authv1.VerifyStepUpChallengeResponse, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	challengeID, err := uuid.Parse(req.ChallengeId)
	if err != nil {
		return nil, MapError(err)
	}

	res, err := s.service.VerifyStepUpChallenge(ctx, challengeID, req.Code)
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.VerifyStepUpChallengeResponse{
		StepUpToken: res.StepUpToken,
		ExpiresIn:   int64(res.ExpiresIn),
	}, nil
}

func (s *server) ForgetPassword(ctx context.Context, req *authv1.ForgetPasswordRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if err := s.service.ForgetPassword(ctx, req.Email); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *server) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	if err := s.service.ResetPassword(ctx, req.Token, req.NewPassword); err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}

func (s *server) BeginGoogleLogin(ctx context.Context, req *emptypb.Empty) (*authv1.BeginGoogleLoginRequest, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	authURL, err := s.service.BeginGoogleLogin(ctx)
	if err != nil {
		return nil, MapError(err)
	}

	return &authv1.BeginGoogleLoginRequest{
		AuthUrl: authURL,
	}, nil
}

func (s *server) VerifyEmail(ctx context.Context, req *authv1.VerifyEmailRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if err := s.service.VerifyEmail(ctx, req.Token); err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil

}

func (s *server) CompleteGoogleLogin(ctx context.Context, req *authv1.CompleteGoogleLoginRequest) (*authv1.TokenPair, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	res, err := s.service.CompleteGoogleLogin(ctx, req.Code, req.State)
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

func (s *server) CreateEmailVerificationToken(ctx context.Context, req *authv1.CreateEmailVerificationTokenRequest) (*emptypb.Empty, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
	if err := s.service.CreateEmailVerificationToken(ctx, req.Email); err != nil {
		return nil, MapError(err)
	}

	return &emptypb.Empty{}, nil
}
