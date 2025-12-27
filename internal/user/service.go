package user

import (
	"context"
	"log/slog"

	"github.com/alkuwaiti/auth/internal/apperrors"
	"github.com/google/uuid"
)

type service struct {
	repo *repo
}

func NewService(repo *repo) *service {
	return &service{
		repo,
	}
}

func (s *service) RegisterUser(ctx context.Context, input RegisterUserInput) (User, error) {
	err := input.validate()
	if err != nil {
		return User{}, err
	}

	exists, err := s.repo.userExistsByEmail(ctx, input.Email)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to check email uniqueness",
			Err: err,
		}
	}
	if exists {
		slog.WarnContext(ctx, "user already exists", "email", input.Email)
		return User{}, &apperrors.InvalidCredentialsError{}
	}

	exists, err = s.repo.userExistsByUsername(ctx, input.Username)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to check username uniqueness",
			Err: err,
		}
	}
	if exists {
		slog.WarnContext(ctx, "user already exists", "username", input.Username)
		return User{}, &apperrors.InvalidCredentialsError{}
	}

	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "error hashing password",
			Err: err,
		}
	}

	user, err := s.repo.registerUser(ctx, input.Username, input.Email, hashedPassword)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to register a user",
			Err: err,
		}
	}

	return user, nil
}

func (s *service) GetUserByEmail(ctx context.Context, email string) (User, error) {
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (s *service) GetUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return User{}, err
	}

	return user, nil
}
