package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *Repo) GetUserByOAuthProvider(ctx context.Context, provider domain.Provider, providerUserID string) (domain.User, error) {
	user, err := r.queries.GetUserByOAuthProvider(ctx, postgres.GetUserByOAuthProviderParams{
		Provider:       string(provider),
		ProviderUserID: providerUserID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, domain.ErrNotFound
		}
		return domain.User{}, err
	}

	return toUserModelFromGetUserByOAuthProviderRow(user), nil
}

func (r *Repo) LinkOAuthProvider(ctx context.Context, userID uuid.UUID, provider domain.Provider, providerUserID string) error {
	return r.queries.LinkOAuthProvider(ctx, postgres.LinkOAuthProviderParams{
		UserID:         userID,
		Provider:       string(provider),
		ProviderUserID: providerUserID,
	})
}

func toUserModelFromGetUserByOAuthProviderRow(row postgres.GetUserByOAuthProviderRow) domain.User {
	return domain.User{
		ID:    row.ID,
		Email: row.Email,
		Roles: row.Roles,
	}
}
