package user

import (
	"context"
	"errors"

	"github.com/alkuwaiti/auth/internal/apperrors"
)

type service struct {
	repo *repo
}

func NewService(repo repo) service {
	return service{
		&repo,
	}
}

func (s *service) RegisterUser(ctx context.Context, input RegisterUserInput) (User, error) {
	err := input.validate()
	if err != nil {
		return User{}, err
	}

	if _, err = s.repo.getUserByEmail(ctx, input.Email); err == nil {
		return User{}, &apperrors.DuplicateError{
			Resource: "user",
			Field:    "email",
			Value:    input.Email,
		}
	} else if !errors.Is(err, ErrUserNotFound) {
		return User{}, &apperrors.InternalError{
			Msg: "failed to query by email",
			Err: err,
		}
	}

	if _, err = s.repo.getUserByUsername(ctx, input.Username); err == nil {
		return User{}, &apperrors.DuplicateError{
			Resource: "user",
			Field:    "username",
			Value:    input.Username,
		}
	} else if !errors.Is(err, ErrUserNotFound) {
		return User{}, &apperrors.InternalError{
			Msg: "failed to query by username",
			Err: err,
		}
	}

	hashedPassword, err := hashPassword(input.Password)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "error hashing password",
			Err: err,
		}
	}

	user, err := s.repo.createUser(ctx, input.Username, input.Email, hashedPassword)
	if err != nil {
		return User{}, &apperrors.InternalError{
			Msg: "failed to create a user",
			Err: err,
		}
	}

	return user, nil
}
