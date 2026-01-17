package grpc

import (
	"errors"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func MapError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.As(err, new(*apperrors.ValidationError)):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.As(err, new(*apperrors.DuplicateError)):
		return status.Error(codes.AlreadyExists, err.Error())

	case errors.As(err, new(*apperrors.InternalError)):
		return status.Error(codes.Internal, err.Error())

	case errors.As(err, new(*apperrors.InvalidCredentialsError)):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.As(err, new(*apperrors.BadRequestError)):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.As(err, new(*apperrors.PasswordReuseError)):
		return status.Error(codes.InvalidArgument, err.Error())

	case errors.As(err, new(*apperrors.RefreshDisabledError)):
		return status.Error(codes.Unavailable, err.Error())

	case errors.As(err, new(*apperrors.ForbiddenError)):
		return status.Error(codes.PermissionDenied, err.Error())

	default:
		slog.Error("unexpected service error", "error", err)
		return status.Error(codes.Internal, "internal server error")
	}
}
