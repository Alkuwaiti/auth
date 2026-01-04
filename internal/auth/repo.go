package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	coreerrors "github.com/alkuwaiti/auth/internal/core/errors"
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

func (r *repo) createSession(ctx context.Context, userID uuid.UUID, expiry time.Time, refreshToken, IPAddress, userAgent string) (Session, error) {
	session, err := r.queries.CreateSession(ctx, postgres.CreateSessionParams{
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
		return Session{}, err
	}

	return toModel(session), nil
}

func (r *repo) getSessionByRefreshToken(ctx context.Context, refreshToken string) (Session, error) {
	session, err := r.queries.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Session{}, coreerrors.ErrSessionNotFound
		}
		return Session{}, err
	}

	return toModel(session), err
}

func (r *repo) revokeSession(ctx context.Context, SessionID uuid.UUID, revocationReason RevocationReason) error {
	if err := r.queries.RevokeSession(ctx, postgres.RevokeSessionParams{
		ID: SessionID,
		RevocationReason: sql.NullString{
			String: string(revocationReason),
			Valid:  revocationReason != "",
		},
	}); err != nil {
		return err
	}

	return nil
}

func (r *repo) updatePasswordAndRevokeSessions(
	ctx context.Context,
	userID uuid.UUID,
	newPasswordHash string,
	reason RevocationReason,
) error {
	return r.execTx(ctx, func(q *postgres.Queries) error {
		if err := q.UpdatePassword(ctx, postgres.UpdatePasswordParams{
			ID:           userID,
			PasswordHash: newPasswordHash,
		}); err != nil {
			return err
		}

		if err := q.RevokeAllUserSessions(ctx, postgres.RevokeAllUserSessionsParams{
			UserID: userID,
			RevocationReason: sql.NullString{
				String: string(reason),
				Valid:  reason != "",
			},
		}); err != nil {
			return err
		}

		return nil
	})
}

type RotateSessionInput struct {
	oldSessionID     uuid.UUID
	userID           uuid.UUID
	expiry           time.Time
	revocationReason RevocationReason
	refreshToken     string
	ipAddress        string
	userAgent        string
}

func (r *repo) rotateSession(
	ctx context.Context,
	input RotateSessionInput,
) error {
	return r.execTx(ctx, func(queries *postgres.Queries) error {
		if err := queries.RevokeSession(ctx, postgres.RevokeSessionParams{
			ID: input.oldSessionID,
			RevocationReason: sql.NullString{
				String: string(input.revocationReason),
				Valid:  input.revocationReason != "",
			},
		}); err != nil {
			return err
		}

		_, err := queries.CreateSession(ctx, postgres.CreateSessionParams{
			UserID:       input.userID,
			RefreshToken: input.refreshToken,
			UserAgent: sql.NullString{
				String: input.userAgent,
				Valid:  input.userAgent != "",
			},
			IpAddress: sql.NullString{
				String: input.ipAddress,
				Valid:  input.ipAddress != "",
			},
			ExpiresAt: input.expiry,
		})
		if err != nil {
			return err
		}

		return nil
	})
}

func (r *repo) revokeAndMarkSessionsCompromised(
	ctx context.Context,
	userID uuid.UUID,
	reason RevocationReason,
) error {
	return r.execTx(ctx, func(q *postgres.Queries) error {
		if err := q.RevokeAllUserSessions(ctx, postgres.RevokeAllUserSessionsParams{
			UserID: userID,
			RevocationReason: sql.NullString{
				String: string(reason),
				Valid:  reason != "",
			},
		}); err != nil {
			return err
		}

		if err := q.MarkSessionsCompromised(ctx, userID); err != nil {
			return err
		}

		return nil
	})
}

func toModel(session postgres.Session) Session {
	var revokedAt *time.Time
	if session.RevokedAt.Valid {
		revokedAt = &session.RevokedAt.Time
	}

	var compromisedAt *time.Time
	if session.CompromisedAt.Valid {
		compromisedAt = &session.CompromisedAt.Time
	}

	return Session{
		ID:               session.ID,
		UserID:           session.UserID,
		RefreshToken:     session.RefreshToken,
		UserAgent:        session.UserAgent.String,
		IPAddress:        session.IpAddress.String,
		CreatedAt:        session.CreatedAt.Time,
		ExpiresAt:        session.ExpiresAt,
		RevokedAt:        revokedAt,
		RevocationReason: RevocationReason(session.RevocationReason.String),
		CompromisedAt:    compromisedAt,
	}
}
