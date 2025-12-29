package user

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/alkuwaiti/auth/internal/core"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type service struct {
	repo *repo
}

func NewService(repo *repo) *service {
	return &service{
		repo,
	}
}

var tracer = otel.Tracer("auth-service/user")

func (s *service) RegisterUser(ctx context.Context, input RegisterUserInput) (User, error) {
	ctx, span := tracer.Start(ctx, "UserService.RegisterUser")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.username", input.Username),
		attribute.String("user.email_hash", core.HashForTelemetry(input.Email)), // optional
	)

	if err := input.validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "validation failed")
		return User{}, err
	}

	exists, err := s.repo.userExistsByEmail(ctx, input.Email)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "email uniqueness check failed")
		return User{}, &apperrors.InternalError{
			Msg: "failed to check email uniqueness",
			Err: err,
		}
	}
	if exists {
		span.SetStatus(codes.Error, "email already exists")
		slog.WarnContext(ctx, "user already exists", "email", input.Email)
		return User{}, &apperrors.InvalidCredentialsError{}
	}

	exists, err = s.repo.userExistsByUsername(ctx, input.Username)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "username uniqueness check failed")
		return User{}, &apperrors.InternalError{
			Msg: "failed to check username uniqueness",
			Err: err,
		}
	}
	if exists {
		span.SetStatus(codes.Error, "username already exists")
		slog.WarnContext(ctx, "user already exists", "username", input.Username)
		return User{}, &apperrors.InvalidCredentialsError{}
	}

	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "password hashing failed")
		return User{}, &apperrors.InternalError{
			Msg: "error hashing password",
			Err: err,
		}
	}

	user, err := s.repo.registerUser(ctx, input.Username, input.Email, hashedPassword)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "user persistence failed")
		return User{}, &apperrors.InternalError{
			Msg: "failed to register a user",
			Err: err,
		}
	}

	span.SetAttributes(
		attribute.String("user.id", user.ID.String()),
	)

	span.SetStatus(codes.Ok, "user registered")
	return user, nil
}

func (s *service) GetUserByEmail(ctx context.Context, email string) (User, error) {
	ctx, span := tracer.Start(ctx, "UserService.GetUserByEmail")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.email_hash", core.HashForTelemetry(email)),
	)

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "user lookup failed")
		return User{}, err
	}

	span.SetAttributes(attribute.String("user.id", user.ID.String()))
	span.SetStatus(codes.Ok, "user fetched")
	return user, nil
}

func (s *service) GetUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	ctx, span := tracer.Start(ctx, "UserService.GetUserByID")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
	)

	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "user lookup failed")
		return User{}, err
	}

	span.SetStatus(codes.Ok, "user fetched")
	return user, nil
}
