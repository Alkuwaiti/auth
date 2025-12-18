// Package user holds user business logic.
package user

import (
	"context"

	"github.com/alkuwaiti/auth/internal/db/postgres"
)

type repo struct {
	queries *postgres.Queries
}

func New(queries *postgres.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) GetAllUsers(ctx context.Context, limit, offset int) ([]User, error) {
	dbUsers, err := r.queries.GetAllUsers(ctx, postgres.GetAllUsersParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, err
	}

	users := make([]User, len(dbUsers))

	for i, user := range dbUsers {
		users[i] = User{
			ID:              user.ID,
			Email:           user.Email,
			Username:        user.Username.String,
			PasswordHash:    user.PasswordHash,
			IsEmailVerified: user.IsEmailVerified,
			IsActive:        user.IsActive,
			CreatedAt:       user.CreatedAt,
			UpdatedAt:       user.UpdatedAt,
		}
	}

	return users, nil
}
