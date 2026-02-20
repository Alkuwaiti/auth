package grpc

import (
	"errors"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func MapError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.Is(err, auth.ErrPasswordReuse):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.Is(err, auth.ErrRefreshDisabled):
		return status.Error(codes.Unavailable, err.Error())

	case errors.Is(err, auth.ErrForbidden):
		return status.Error(codes.PermissionDenied, err.Error())

	case errors.Is(err, auth.ErrChallengeExpired):
		return status.Error(codes.ResourceExhausted, err.Error())

	case errors.Is(err, auth.ErrInvalidMFACode):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.Is(err, (auth.ErrInvalidMFAChallenge)):
		return status.Error(codes.InvalidArgument, err.Error())

	default:
		slog.Error("unexpected service error", "error", err)
		return status.Error(codes.Internal, "internal server error")
	}
}
