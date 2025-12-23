// Package user holds user business logic.
package user

import (
	"context"
	"database/sql"
	"errors"

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

func (r *repo) UserExistsByEmail(ctx context.Context, email string) (bool, error) {
	exists, err := r.queries.UserExistsByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, err
	}

	return exists, nil
}

func (r *repo) UserExistsByUsername(ctx context.Context, username string) (bool, error) {
	exists, err := r.queries.UserExistsByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, err
	}
	return exists, nil
}

func (r *repo) registerUser(ctx context.Context, username, email, passwordHash string) (User, error) {
	user, err := r.queries.RegisterUser(ctx, postgres.RegisterUserParams{
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
