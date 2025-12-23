package user

import (
	"context"
	"errors"

	"github.com/alkuwaiti/auth/internal/apperrors"
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

	exists, err := s.repo.UserExistsByEmail(ctx, input.Email)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to check email uniqueness",
			Err: err,
		}
	}
	if exists {
		return User{}, &apperrors.DuplicateError{
			Resource: "user",
			Field:    "email",
			Value:    input.Email,
		}
	}

	exists, err = s.repo.UserExistsByUsername(ctx, input.Username)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to check username uniqueness",
			Err: err,
		}
	}
	if exists {
		return User{}, &apperrors.DuplicateError{
			Resource: "user",
			Field:    "username",
			Value:    input.Username,
		}
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
