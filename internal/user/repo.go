// Package user holds user business logic.
package user

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alkuwaiti/auth/internal/core"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

type repo struct {
	queries *postgres.Queries
}

func NewRepo(queries *postgres.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) userExistsByEmail(ctx context.Context, email string) (bool, error) {
	exists, err := r.queries.UserExistsByEmail(ctx, email)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *repo) userExistsByUsername(ctx context.Context, username string) (bool, error) {
	exists, err := r.queries.UserExistsByUsername(ctx, username)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (r *repo) registerUser(ctx context.Context, username, email, passwordHash string) (User, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return User{}, err
	}

	user, err := r.queries.RegisterUser(ctx, postgres.RegisterUserParams{
		ID:           id,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return User{}, err
	}

	return toModel(user), nil
}

func (r *repo) getUserByEmail(ctx context.Context, email string) (User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, core.ErrUserNotFound
		}
		return User{}, err
	}

	return toModel(user), nil
}

func (r *repo) getUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	user, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, core.ErrUserNotFound
		}
		return User{}, err
	}

	return toModel(user), nil
}

func (r *repo) updatePassword(ctx context.Context, userID uuid.UUID, newPasswordHash string) error {
	if err := r.queries.UpdatePassword(ctx, postgres.UpdatePasswordParams{
		ID:           userID,
		PasswordHash: newPasswordHash,
	}); err != nil {
		return err
	}

	return nil
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
