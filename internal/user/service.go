package user

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type service struct {
	repo repo
}

func (s *service) RegisterUser(ctx context.Context, username, email, password string) (User, error) {
	existingUser, err := s.repo.getUserByEmail(ctx, email)
	if err != nil {
		return existingUser, fmt.Errorf("failed to query user by email: %w", err)
	}

	if existingUser.ID != uuid.Nil {
		return User{}, fmt.Errorf("user already exists")
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("error hashing password: %w", err)
	}

	user, err := s.repo.createUser(ctx, username, email, hashedPassword)
	if err != nil {
		return User{}, fmt.Errorf("failed to create a user: %w", err)
	}

	return user, nil
}
