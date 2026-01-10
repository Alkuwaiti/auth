package user

import (
	"context"

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

func (s *service) GetUserByEmail(ctx context.Context, email string) (core.User, error) {
	ctx, span := tracer.Start(ctx, "UserService.GetUserByEmail")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.email_hash", core.HashForTelemetry(email)),
	)

	user, err := s.repo.getUserByEmail(ctx, email)
	if err != nil {
		return core.User{}, err
	}

	span.SetAttributes(attribute.String("user.id", user.ID.String()))
	span.SetStatus(codes.Ok, "user fetched")

	return user, nil
}

func (s *service) GetUserByID(ctx context.Context, userID uuid.UUID) (core.User, error) {
	ctx, span := tracer.Start(ctx, "UserService.GetUserByID")
	defer span.End()

	span.SetAttributes(
		attribute.String("user.id", userID.String()),
	)

	user, err := s.repo.getUserByID(ctx, userID)
	if err != nil {
		return core.User{}, err
	}

	span.SetStatus(codes.Ok, "user fetched")
	return user, nil
}

func (s *service) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	ctx, span := tracer.Start(ctx, "UserService.UpdatePassword")
	defer span.End()

	exists, err := s.repo.userExistsByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (s *service) UserExistsByUsername(ctx context.Context, username string) (bool, error) {
	ctx, span := tracer.Start(ctx, "UserService.UpdatePassword")
	defer span.End()

	exists, err := s.repo.userExistsByUsername(ctx, username)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (s *service) CreateUser(ctx context.Context, username, email, passwordHash string) (core.User, error) {
	ctx, span := tracer.Start(ctx, "UserService.CreateUser")
	defer span.End()

	id, err := uuid.NewV7()
	if err != nil {
		return core.User{}, err
	}

	user, err := s.repo.createUser(ctx, id, username, email, passwordHash)
	if err != nil {
		return core.User{}, err
	}

	return user, nil
}
