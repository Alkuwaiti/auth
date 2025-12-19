package grpc

import (
	"context"
	"log/slog"

	userv1 "github.com/alkuwaiti/auth/pb/pbuser/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) RegisterUser(ctx context.Context, req *userv1.RegisterUserRequest) (*userv1.User, error) {
	if req == nil {
		slog.ErrorContext(ctx, "Invalid request: request is nil")
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}
}
