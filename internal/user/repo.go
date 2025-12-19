// Package user holds user business logic.
package user

import (
	"context"

	"github.com/alkuwaiti/auth/internal/db/postgres"
)

type repo struct {
	queries *postgres.Queries
}

func NewRepo(queries *postgres.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) getUserByEmail(ctx context.Context, email string) (User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return User{}, err
	}

	return toModel(user), nil
}

func (r *repo) getUserByUsername(ctx context.Context, username string) (User, error) {
	user, err := r.queries.GetUserByUsername(ctx, username)
	if err != nil {
		return User{}, err
	}

	return toModel(user), nil
}

func (r *repo) createUser(ctx context.Context, username, email, passwordHash string) (User, error) {
	user, err := r.queries.CreateUser(ctx, postgres.CreateUserParams{
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return User{}, err
	}

	return toModel(user), nil
}

func toModel(postgresUser postgres.User) User {
	return User{
		ID:              postgresUser.ID,
		Email:           postgresUser.Email,
		Username:        postgresUser.Username,
		PasswordHash:    postgresUser.PasswordHash,
		IsEmailVerified: postgresUser.IsEmailVerified,
		IsActive:        postgresUser.IsActive,
		CreatedAt:       postgresUser.CreatedAt,
		UpdatedAt:       postgresUser.UpdatedAt,
	}
}
