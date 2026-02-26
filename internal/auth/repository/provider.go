package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alkuwaiti/auth/internal/auth/domain"
	"github.com/alkuwaiti/auth/internal/db/postgres"
	"github.com/google/uuid"
)

func (r *repo) GetSocialAccountByProviderID(ctx context.Context, provider domain.Provider, providerUserID string) (domain.SocialAccount, error) {
	socialAccount, err := r.queries.GetUserByProviderID(ctx, postgres.GetUserByProviderIDParams{
		Provider:       string(provider),
		ProviderUserID: providerUserID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.SocialAccount{}, domain.ErrNotFound
		}
	}

	return toSocialAccount(socialAccount), nil
}

func (r *repo) LinkOAuthProvider(ctx context.Context, userID uuid.UUID, provider domain.Provider, providerUserID string) error {
	return r.queries.LinkOAuthProvider(ctx, postgres.LinkOAuthProviderParams{
		UserID:         userID,
		Provider:       string(provider),
		ProviderUserID: providerUserID,
	})
}

func toSocialAccount(row postgres.SocialAccount) domain.SocialAccount {
	return domain.SocialAccount{
		ID:             row.ID,
		UserID:         row.UserID,
		Provider:       domain.Provider(row.Provider),
		ProviderUserID: row.ProviderUserID,
		CreatedAt:      row.CreatedAt,
	}
}
