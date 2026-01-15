// Package user holds user business logic.
package user

import (
	"context"
	"database/sql"
	"errors"
	"time"

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

func (r *repo) userExists(ctx context.Context, username, email string) (bool, error) {
	exists, err := r.queries.UserExists(ctx, postgres.UserExistsParams{
		Username: username,
		Email:    email,
	})
	if err != nil {
		return false, err
	}

	return exists, nil
}

func (r *repo) createUser(ctx context.Context, userID uuid.UUID, username, email, passwordHash string) (core.User, error) {
	user, err := r.queries.CreateUser(ctx, postgres.CreateUserParams{
		ID:           userID,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return core.User{}, err
	}

	return toModel(user), nil
}

func (r *repo) getUserByEmail(ctx context.Context, email string) (core.User, error) {
	user, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}

	return toModel(user), nil
}

func (r *repo) getUserByID(ctx context.Context, userID uuid.UUID) (core.User, error) {
	user, err := r.queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return core.User{}, core.ErrUserNotFound
		}
		return core.User{}, err
	}

	return toModel(user), nil
}

func toModel(postgresUser postgres.User) core.User {
	var deletedAt *time.Time
	if postgresUser.DeletedAt.Valid {
		deletedAt = &postgresUser.DeletedAt.Time
	}

	var deletionReason *core.DeletionReason
	if postgresUser.DeletionReason.Valid {
		dr := core.DeletionReason(postgresUser.DeletionReason.String)
		deletionReason = &dr
	}

	return core.User{
		ID:              postgresUser.ID,
		Email:           postgresUser.Email,
		Username:        postgresUser.Username,
		PasswordHash:    postgresUser.PasswordHash,
		IsEmailVerified: postgresUser.IsEmailVerified,
		IsActive:        postgresUser.IsActive,
		CreatedAt:       postgresUser.CreatedAt,
		UpdatedAt:       postgresUser.UpdatedAt,
		DeletedAt:       deletedAt,
		DeletionReason:  deletionReason,
	}
}
