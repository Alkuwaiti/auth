package user

import (
	"context"
	"fmt"
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

	existingUser, err := s.repo.getUserByEmail(ctx, input.email)
	if err != nil {
		return existingUser, fmt.Errorf("failed to query user by email: %w", err)
	}

	if existingUser.Email == input.email {
		return User{}, fmt.Errorf("user already exists")
	}

	existingUser, err = s.repo.getUserByUsername(ctx, input.username)
	if err != nil {
		return existingUser, fmt.Errorf("failed to query user by username: %w", err)
	}

	if existingUser.Username == input.username {
		return User{}, fmt.Errorf("user already exists")
	}

	hashedPassword, err := hashPassword(input.password)
	if err != nil {
		return User{}, fmt.Errorf("error hashing password: %w", err)
	}

	user, err := s.repo.createUser(ctx, input.username, input.email, hashedPassword)
	if err != nil {
		return User{}, fmt.Errorf("failed to create a user: %w", err)
	}

	return user, nil
}
