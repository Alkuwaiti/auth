// Package repos uses the db.
package repos

import (
	"context"

	"github.com/alkuwaiti/auth/internal/services/auth/model"
	"github.com/alkuwaiti/auth/internal/services/auth/repos/pgauth"
)

type repo struct {
	queries *pgauth.Queries
}

func New(queries *pgauth.Queries) *repo {
	return &repo{
		queries: queries,
	}
}

func (r *repo) GetAllUsers(ctx context.Context, limit, offset int) ([]model.User, error) {
	dbUsers, err := r.queries.GetAllUsers(ctx, pgauth.GetAllUsersParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, err
	}

	users := make([]model.User, len(dbUsers))

	for i, user := range dbUsers {
		users[i] = model.User{
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
