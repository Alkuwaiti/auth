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
	db      *sql.DB
	queries *postgres.Queries
}

func NewRepo(db *sql.DB) *repo {
	return &repo{
		db:      db,
		queries: postgres.New(db),
	}
}

func (r *repo) execTx(ctx context.Context, fn func(*postgres.Queries) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	qtx := r.queries.WithTx(tx)

	if err := fn(qtx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
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

func (r *repo) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	if err := r.queries.RevokeAllUserSessions(ctx, userID); err != nil {
		return err
	}

	return nil
}

func (r *repo) RotateSession(
	ctx context.Context,
	oldSessionID uuid.UUID,
	userID uuid.UUID,
	expiry time.Time,
	refreshToken string,
	ipAddress string,
	userAgent string,
) error {
	return r.execTx(ctx, func(queries *postgres.Queries) error {
		if err := queries.RevokeSession(ctx, oldSessionID); err != nil {
			return err
		}

		err := queries.CreateSession(ctx, postgres.CreateSessionParams{
			UserID:       userID,
			RefreshToken: refreshToken,
			UserAgent: sql.NullString{
				String: userAgent,
				Valid:  userAgent != "",
			},
			IpAddress: sql.NullString{
				String: ipAddress,
				Valid:  ipAddress != "",
			},
			ExpiresAt: expiry,
		})
		if err != nil {
			return err
		}

		return nil
	})
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
