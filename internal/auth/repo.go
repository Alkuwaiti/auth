package auth

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

func (r *repo) CreateSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) error {
	err := r.queries.CreateSession(ctx, postgres.CreateSessionParams{
		UserID:       userID,
		RefreshToken: refreshToken,
		UserAgent: sql.NullString{
			String: userAgent,
			Valid:  userAgent != "",
		},
		IpAddress: sql.NullString{
			String: IPAddress,
			Valid:  IPAddress != "",
		},
		ExpiresAt: expiry,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *repo) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (Session, error) {
	session, err := r.queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, core.ErrSessionNotFound
		}
		return Session{}, err
	}

	return toModel(session), err
}

func (r *repo) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if err := r.queries.RevokeSession(ctx, sessionID); err != nil {
		return err
	}

	return nil
}

func toModel(session postgres.Session) Session {
	return Session{
		ID:           session.ID,
		UserID:       session.UserID,
		RefreshToken: session.RefreshToken,
		UserAgent:    session.UserAgent.String,
		IPAddress:    session.IpAddress.String,
		CreatedAt:    session.CreatedAt.Time,
		ExpiresAt:    session.ExpiresAt,
		RevokedAt:    session.RevokedAt.Time,
	}
}
